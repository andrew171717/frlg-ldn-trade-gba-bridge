#!/usr/bin/env python3
"""linkbridge.py — Serial bridge: RP2040-Zero <-> Raspberry Pi LDN stack.

Run this on the Raspberry Pi while the RP2040-Zero is plugged into the GBA
and connected to this board via GPIO wires.

Hardware wiring
---------------
RP2040-Zero                   Raspberry Pi
  GPIO0 (UART0 TX)   -------> GPIO15 / pin 10  (RX / ttyAMA0)
  GPIO1 (UART0 RX)   <------- GPIO14 / pin 8   (TX / ttyAMA0)
  GND                -------> any GND pin

Pi UART setup (Raspberry Pi 3/4/5):
  1. Add  dtoverlay=disable-bt  to /boot/firmware/config.txt
  2. REMOVE  console=serial0,115200  from /boot/firmware/cmdline.txt
     (keep console=tty1 for HDMI; removing the serial0 entry stops the
     kernel from printing boot messages over our bridge UART)
  3. Reboot

Run as root (required for ldn.scan() -> nl80211 / raw sockets):
  sudo venv/bin/python3 linkbridge.py [--port /dev/ttyAMA0] [--phy phy0]

Wire protocol (line-based ASCII, \\n terminated)
-------------------------------------------------
RP2040 -> Pi:  SCAN_START\\n      start scanning the LDN for FRLG lobby beacons
               SCAN_RESULT\\n     request current host list (instant reply)
               SCAN_STOP\\n       stop scanning and clear the cache

Pi -> RP2040:  HOSTS <N>\\n              (only in response to SCAN_RESULT)
               HOST <w0> ... <w6>\\n      (N lines; 7 LE u32 words, GBA 0x1D format)
               ERR <msg>\\n              on unexpected errors
               HOST_DATA <N> w0 ...\\n  N words; w0=LLSF byte count, w1..wN=Switch NI LLSF
                                       bytes packed as u32 LE (NI_START→NI_END from the host).
                                       rfu_STC_CHILD_analyzeRecvPacket reads w0 as
                                       frames_remaining and w1.. as the NI sub-frame data.
               DISCONNECT\\n            Switch rejected or cleanly disconnected

HOST word layout — 7 plaintext words, GBA wireless adapter 0x1D BroadcastReadPoll format:
  w0 = id(u16) | slot(u8=0) | 0x00
  w1 = serialNo(u16=0x0002) | gname[0-1]
  w2 = gname[2-5]   w3 = gname[6-9]
  w4 = gname[10-12] | ~checksum          ← checksum byte at w4[3]
  w5 = uname[0-3]   w6 = uname[4-7]

  gname  = 13 bytes (RFU_GAME_NAME_LENGTH): plaintext RfuGameData struct
             with ACTIVITY_TRADE, trainer ID, and game version.
  uname  =  8 bytes (RFU_USER_NAME_LENGTH): GBA charmap trainer name + 0xFF pad.
  serialNo = 0x0002 (RFU_SERIAL_GAME), always plaintext.
  checksum = ~( sum(gname[0:8]) + sum(uname[0:8]) ) mod 256
             GBA silently drops partners with a bad checksum.

All fields are PLAINTEXT.  The NSO emulates a GBA wireless adapter: the
GBA's rfu_REQ_configGameData call hands a 30-byte RfuTgtData struct to the
NSO via svc, and the NSO places it verbatim in application_data[0x5C:] of
the LDN beacon.  The receiving Switch's NSO reads it back and presents it
to its GBA — no encoding on either side.  linkbridge extracts the
RfuTgtData from each beacon and maps it to the 7-word 0x1D format with a
single correction: zero mbootFlag (byte 3) and skip the gname[14] padding
byte (byte 20), so uname aligns correctly at byte 20 of the 28-byte packet.

Notes:
  - SCAN_START is idempotent; sending it while already scanning is a no-op.
  - SCAN_RESULT is answered immediately with whatever the last completed scan
    found, so the RP2040 never waits for a full LDN scan to finish.
  - LDN scans take ~2-3 s each.  The background loop runs them continuously;
    hosts not seen for 6+ seconds are removed from the cache.
  - SCAN_STOP clears the cache, so the next SCAN_START begins fresh.
  - No LDN join, Pia handshake, or LP block exchange is needed to detect
    that a host is present — beacon presence is sufficient.
"""

import argparse
import logging
import queue
import sys
import threading
import time

import serial  # pyserial

from frlgsim.rfu_advert_map import decode_record, base85_encode, frlg_text
from frlgsim.transport import LiveTransport
from switch_session import SwitchSession

log = logging.getLogger("linkbridge")


# ---------------------------------------------------------------------------
# Continuous background join + maintain loop
# ---------------------------------------------------------------------------

class ScanManager:
    """Continuously scans the LDN for FRLG lobby beacons and maintains a cache
    of discovered comm_ids (one entry per host).

    The NSO LDN beacon uses proprietary Nintendo encoding that cannot be used
    directly as GBA wireless adapter wire data.  _send_hosts() synthesises the
    correct plaintext librfu words from the configured trainer identity instead.

    Thread safety: all mutable state protected by self._lock.
    """

    # Seconds between successive LDN beacon scans.
    _SCAN_INTERVAL_S = 2.0
    # Remove a cached host if not seen in this many seconds.
    _HOST_EXPIRY_S   = 6.0

    def __init__(self, phyname: str, keys_path: str, nickname: str = "RPI") -> None:
        self._phyname   = phyname
        self._keys_path = keys_path
        self._nickname  = nickname   # kept for potential future use
        self._lock      = threading.Lock()
        self._active    = False
        # Cache: list of {"comm_id": int, "words": list[int], "last_seen": float}
        self._hosts: list[dict] = []

        self._thread = threading.Thread(target=self._loop, daemon=True, name="scan-loop")
        self._thread.start()

    # ------------------------------------------------------------------
    # Control API (called from the serial-I/O thread)
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Enter scan mode.  Idempotent."""
        with self._lock:
            already = self._active
            self._active = True
            if not already:
                self._hosts.clear()
        if not already:
            log.info("[SCAN] scan mode started")

    def stop(self) -> None:
        """Exit scan mode and clear the cache."""
        with self._lock:
            self._active = False
            self._hosts.clear()
        log.info("[SCAN] scan mode stopped; cache cleared")

    def get_hosts(self) -> list[dict]:
        """Return up to 4 currently cached beacon entries."""
        now = time.monotonic()
        with self._lock:
            valid = [h for h in self._hosts
                     if now - h["last_seen"] < self._HOST_EXPIRY_S]
            return valid[:4]

    # ------------------------------------------------------------------
    # Background scan loop
    # ------------------------------------------------------------------

    def _loop(self) -> None:
        while True:
            with self._lock:
                active = self._active

            if not active:
                time.sleep(0.05)
                continue

            try:
                self._run_session()
            except Exception as e:
                log.error("[SCAN] scan error: %s", e)

            # Prune stale entries; wait before the next scan.
            now = time.monotonic()
            with self._lock:
                self._hosts = [
                    h for h in self._hosts
                    if now - h["last_seen"] < self._HOST_EXPIRY_S
                ]

            time.sleep(self._SCAN_INTERVAL_S)

    @staticmethod
    def _dump_app_data(app_raw: bytes, comm_id: int) -> None:
        """Print the full LDN beacon application_data in a hex+ASCII layout so
        we can locate the obfuscated trainer name and TID by eye."""
        n = len(app_raw)
        log.info("[BEACON] comm_id=0x%016x  application_data (%d bytes):", comm_id, n)
        # Hex dump: 16 bytes per row, offset | hex | ASCII
        for row in range(0, n, 16):
            chunk = app_raw[row:row + 16]
            hex_part  = " ".join(f"{b:02x}" for b in chunk)
            # Show printable ASCII; use '.' for everything else
            asc_part  = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
            log.info("[BEACON]   %04x:  %-47s  |%s|", row, hex_part, asc_part)
        # Also highlight the region after the 0x5C Pia header (the GBA emulator payload)
        if n > 0x5C:
            gba = app_raw[0x5C:]
            log.info("[BEACON] GBA payload (after 0x5C Pia header, %d bytes): %s",
                     len(gba), gba.hex())
            # Print each byte with its offset so it's easy to reference
            annotated = "  ".join(f"{i:02d}:{b:02x}" for i, b in enumerate(gba))
            log.info("[BEACON]   %s", annotated)

    def _run_session(self) -> None:
        """Scan the LDN for FRLG broadcast beacons and cache discovered hosts.

        We only need to know that a host *exists* (to present it in the GBA
        nearby-players list).  The actual wire words (trainer name, TID, etc.)
        are synthesised from the configured trainer identity by _send_hosts(),
        not extracted from the beacon payload, because the NSO beacon uses
        proprietary encoding that is not the same as the librfu plaintext wire
        format the GBA expects.
        """
        try:
            import trio
            import ldn
            from frlgsim.transport import free_radio, _b85_decode
        except ImportError as e:
            log.error("[SCAN] missing dependency: %s — install requirements.txt", e)
            return

        free_radio({self._phyname}, log.info)

        results: list[dict] = []

        async def _scan():
            keys = ldn.load_keys(self._keys_path)
            log.info("[SCAN] scanning for FRLG LDN beacon...")
            networks = await ldn.scan(keys, phyname=self._phyname)
            log.debug("[SCAN] raw scan: %d network(s)", len(networks))

            for n in networks:
                comm_id = getattr(n, "local_communication_id", 0)
                scene   = getattr(n, "scene_id", 0)
                num_p   = getattr(n, "num_participants", 0)
                max_p   = getattr(n, "max_participants", 0)
                app_raw = bytes(getattr(n, "application_data", b"") or b"")
                log.info("[SCAN] network comm_id=0x%016x scene=%d %d/%d app_data=%dB",
                         comm_id, scene, num_p, max_p, len(app_raw))

                # The NSO emulates a GBA wireless adapter: the GBA's rfu_REQ_configGameData
                # call hands a 30-byte RfuTgtData struct to the NSO via svc, and the NSO
                # places it verbatim in application_data[0x5C:] of the LDN beacon.
                # The receiving Switch's NSO reads it back out and presents it to its GBA.
                # There is no encoding — the data is plaintext, same as the real wireless
                # adapter RF protocol.
                RFU_TGT_DATA_OFFSET = 0x5C
                RFU_TGT_DATA_LEN    = 30

                # Dump the full application_data so we can locate the
                # obfuscated trainer name and TID within it.
                self._dump_app_data(app_raw, comm_id)

                if len(app_raw) < RFU_TGT_DATA_OFFSET + RFU_TGT_DATA_LEN:
                    log.warning("[SCAN] app_data too short (%dB), skipping", len(app_raw))
                    continue

                # The RFU payload will be a custom base85-encoded blob.
                gba_payload = app_raw[RFU_TGT_DATA_OFFSET:]
                rfutgt = None
                try:
                    decoded = _b85_decode(gba_payload)
                    # Log the decoded blob we received (may be shorter than expected)
                    log.info("[SCAN] decoded (len=%d) %s", len(decoded), decoded.hex())
                    if len(decoded) >= RFU_TGT_DATA_LEN:
                        rfutgt = decoded[:RFU_TGT_DATA_LEN]
                    else:
                        # Accept shorter decoded payloads by padding with zeros to the
                        # expected RFU_TGT_DATA_LEN so downstream code can consume it.
                        rfutgt = decoded.ljust(RFU_TGT_DATA_LEN, b"\x00")
                        log.info("[SCAN] decoded RFU payload shorter than %d; padded to %d bytes",
                                 len(decoded), RFU_TGT_DATA_LEN)
                    log.info("[SCAN] RFU raw (decoded) %s", rfutgt.hex())
                except Exception:
                    log.debug("[SCAN] RFU payload base85 decode failed; discarding", exc_info=True)
                    log.info("[SCAN] skipping host comm_id=0x%016x: no valid RFU payload", comm_id)
                    continue

                results.append({
                    "comm_id":  comm_id,
                    "rfutgt":   rfutgt,
                    "last_seen": 0.0,
                })

        try:
            trio.run(_scan)
        except BaseException as e:
            log.error("[SCAN] ldn.scan() raised: %s", e)
            return

        now = time.monotonic()

        with self._lock:
            if not self._active:
                return
            for r in results:
                r["last_seen"] = now
            self._hosts = results

        if results:
            log.info("[SCAN] cached %d host(s) from beacon scan.", len(results))


# ---------------------------------------------------------------------------
# ConnectManager -- handles the GBA 0x1F Connect / 0x20 IsConnectionComplete
# sequence on the Pi side.
#
# When the RP2040 sends "CONNECT 0x<rfu_id>", the Pi needs to:
#   1. Stop the background LDN scan (the radio can't scan AND associate
#      at the same time).
#   2. Find the cached host whose rfu_id matches and get its comm_id.
#   3. Join that LDN session via LiveTransport.start() -- this can take a
#      few seconds.
#   4. Report the result: "CONN_COMPLETE <clientNum> <our_id_hex>" on
#      success, "CONN_FAILED <reason>" on failure.
#
# The RP2040 just polls 0x20 IsConnectionComplete in a tight GBA loop
# (returning 0x01000000 while pending).  The reply arrives via the normal
# bridge_poll_rx() drain, so no extra synchronisation is needed on the
# RP2040 side.
#
# Thread safety: _lock protects all mutable state.
# ---------------------------------------------------------------------------


class ConnectManager:
    """Manages a single async LDN join on behalf of the GBA's 0x1F command."""

    IDLE     = "idle"
    PENDING  = "pending"
    COMPLETE = "complete"
    FAILED   = "failed"

    def __init__(self, phyname: str, keys_path: str) -> None:
        self._phyname   = phyname
        self._keys_path = keys_path
        self._lock      = threading.Lock()
        self._state     = self.IDLE
        self._transport: LiveTransport | None = None
        self._thread: threading.Thread | None = None
        # Signals the Pia session loop (running in the _do_join thread after CONN_COMPLETE)
        # to stop.  Set by reset(); cleared at the start of a new connect().
        self._sim_stop  = threading.Event()
        # Active SwitchSession (set during _run_pia, cleared on exit/reset).
        # The main UART loop calls set_gba_data() on us, which routes here.
        self._session: "SwitchSession | None" = None
        # HOST_DATA flow control: RP2040 sends READY after each 0x26 to request
        # the next slot.  Pi queues HOST_DATA strings and sends one per READY.
        # If READY arrives before anything is queued, hd_ready_pending is set so
        # the next enqueue sends immediately instead of queuing.
        self._hd_queue:        queue.SimpleQueue = queue.SimpleQueue()
        self._hd_lock:         threading.Lock    = threading.Lock()
        self._hd_ready_pending: bool             = False
        # NI handshake: combined per-round responses after JOIN_GROUP_OK.
        # For each GBA NISender sub-frame (ack=0, state 1-3) we reply with one
        # HOST_DATA containing BOTH the parent's own NI sub-frame for that state
        # AND the PARENT LLSF ACK of the GBA's sub-frame — matching the real
        # wireless adapter which coalesces both into a single response per round.
        # _parent_ni_raw_frames[state] = raw LLSF bytes for that parent NI sub-frame.
        # _pia_port is set while _run_pia runs so set_gba_data() can send HOST_DATA.
        self._in_ni_handshake:     bool                    = False
        self._ni_b_expect:         int                     = 0   # 0=inactive, 1-3=next state Phase B expects
        self._client_num_cached:   int                     = 0
        self._pia_port:            "serial.Serial | None"  = None
        self._parent_ni_raw_frames: "dict[int, bytes]"     = {}

    # ------------------------------------------------------------------
    # Called from the serial-I/O thread
    # ------------------------------------------------------------------

    def connect(self, rfu_id: int, broadcast_words: "list[int] | None",
                scanner: "ScanManager", port: serial.Serial) -> None:
        """Start an async LDN join for the host with the given rfu_id. 
        Stops the background scanner (both compete for the radio), finds
        the matching host in the scan cache, then spawns a thread that
        calls LiveTransport.start() and writes the result back over
        'port' when done.
        broadcast_words: the 6 u32 words from the GBA's 0x16 Broadcast
            (its own gname/uname identity).  Used as application_data in
            the LDN ConnectNetworkParam so the host Switch sees our real
            GBA trainer identity.  May be None if the GBA skipped 0x16.
        """
        with self._lock:
            if self._state == self.PENDING:
                log.warning("[CONN] connect() called while already pending -- ignoring")
                return
            # Tear down any previous transport and stop any running Pia loop.
            self._sim_stop.set()
            self._teardown_locked()
            self._sim_stop.clear()   # arm for the new session
            self._state = self.PENDING

        # Snapshot the host list BEFORE stopping the scanner --
        # stop() calls _hosts.clear(), so doing this after would always
        # give an empty list and comm_id would be None every time.
        hosts = scanner.get_hosts()

        # Now stop the scanner so the radio is free for the LDN join.
        scanner.stop()

        # Find the comm_id matching this rfu_id in the cached host list.
        comm_id = None
        for h in hosts:
            try:
                r = decode_record(h["rfutgt"])
                if r["rfu_id"] == rfu_id:
                    comm_id = h["comm_id"]
                    break
            except Exception:
                pass

        if comm_id is None:
            log.warning("[CONN] rfu_id=0x%04x not found in cache (%d hosts); "
                        "joining any available FRLG network", rfu_id, len(hosts))

        # Build application_data from the GBA's broadcast identity.
        # Also keep the raw rfutgt record to extract trainer name/TID for the
        # NI game-data handshake (so the Switch sees the real GBA trainer).
        rfutgt:   "bytes | None" = None
        app_data: "bytes | None" = None
        if broadcast_words and len(broadcast_words) == 6:
            try:
                rfutgt = _broadcast_words_to_rfutgt(rfu_id, broadcast_words)
                # base85_encode produces 30 bytes (24-byte record -> 30 chars).
                # The ldn lib prepends the Pia system header itself; we supply
                # only the 30-byte game payload.
                app_data = base85_encode(rfutgt)
                log.info("[CONN] built application_data (%d bytes) from broadcast: %s",
                         len(app_data), app_data.hex())
            except Exception as e:
                log.warning("[CONN] could not build application_data: %s", e)

        log.info("[CONN] starting LDN join for rfu_id=0x%04x comm_id=%s",
                 rfu_id, f"0x{comm_id:016x}" if comm_id is not None else "any")

        t = threading.Thread(
            target=self._do_join,
            args=(rfu_id, comm_id, app_data, rfutgt, port),
            daemon=True,
            name="ldn-join",
        )
        with self._lock:
            self._thread = t
        t.start()

    def set_gba_data(self, words: list) -> None:
        """Route GBA_DATA from the UART loop to the active SwitchSession.

        Called from the main serial-I/O thread each time the RP2040 sends a
        GBA_DATA line (i.e. each 0x24/0x25 SendData command from the GBA).
        `words` are u32 hex values straight from the UART line; set_gba_words()
        handles the u32→u16 unpacking internally.

        During the NI handshake phase the GBA's NISender is sending its own
        NI sub-frames (NI_START → NI → NI_END) and waiting for PARENT LLSF
        ACKs (ack=1) in each 0x26 response.  Without those ACKs the sender
        retransmits forever.  We synthesise the ACK here and push it to the
        HOST_DATA queue so the READY handler can forward it.
        GBA payload layout: word[0]=framing header, word[1] low-u16=CHILD NI LLSF.
        """
        s = self._session
        if s is not None:
            # word[0] is the GBA's slot identifier (0x900=slot0, 0x12000=slot1);
            # it is part of the slot data the Switch needs and must not be stripped.
            s.set_gba_words(words)

        port = self._pia_port
        if not self._in_ni_handshake or port is None or len(words) < 2:
            return
        child_llsf = words[1] & 0xFFFF
        state = (child_llsf >> 10) & 0x1F
        ack   = (child_llsf >> 9)  & 1
        n     = (child_llsf >> 7)  & 3
        phase = (child_llsf >> 5)  & 3

        if ack == 0 and 1 <= state <= 3:
            # Phase A — GBA's NISender (ack=0).
            # Send ONE combined HOST_DATA: [PARENT LLSF ACK (3 bytes)] + [parent NI
            # sub-frame for this state (from _parent_ni_raw_frames)].  This matches
            # the real wireless adapter which coalesces both into a single 0x26 reply.
            # rfu_STC_CHILD_analyzeRecvPacket then sees:
            #   ack=1 LLSF → NISender advances to next state
            #   ack=0 LLSF + payload → NIReceiver ingests the parent NI sub-frame
            bm_slot = 1 << self._client_num_cached
            parent_ack_int = (state << 14) | (bm_slot << 18) | (1 << 13) | (n << 11) | (phase << 9)
            ack_bytes = parent_ack_int.to_bytes(3, "little")
            ni_frm = self._parent_ni_raw_frames.get(state, b"")
            combined = ack_bytes + ni_frm
            combined_words = [len(combined)]
            for i in range(0, len(combined), 4):
                combined_words.append(int.from_bytes(
                    combined[i:i + 4].ljust(4, b"\x00"), "little"))
            combined_msg = "HOST_DATA {} {}".format(
                len(combined_words), " ".join(f"0x{w:08X}" for w in combined_words))
            log.info("[NI-A] GBA state=%d n=%d ph=%d → %s", state, n, phase, combined_msg)
            self._enqueue_host_data(combined_msg, port)
            # After delivering NI_START (state=1) to the GBA's NIReceiver, arm
            # Phase B to deliver state=2 once the GBA ACKs state=1.  NIReceiver
            # ignores sub-frames that arrive in later NISender rounds; it only
            # processes each sub-frame in response to its own sequential ACKs.
            if state == 1:
                self._ni_b_expect = 2   # next to deliver: parent NI state=2

        elif ack == 1 and 1 <= state <= 3:
            # Phase B — GBA's NIReceiver is ACKing the sub-frame we last delivered.
            # _ni_b_expect encodes the NEXT sub-frame to send: 0=not armed,
            # 2=send parent NI state=2, 3=send NI_END, 4=clear (done).
            # Fire only when GBA's ack=1 state == _ni_b_expect - 1.
            if self._ni_b_expect > 0 and state == self._ni_b_expect - 1:
                if state < 3:
                    next_state = state + 1
                    frm = self._parent_ni_raw_frames.get(next_state, b"")
                    if frm:
                        frm_words = [len(frm)]
                        for i in range(0, len(frm), 4):
                            frm_words.append(int.from_bytes(
                                frm[i:i + 4].ljust(4, b"\x00"), "little"))
                        frm_msg = "HOST_DATA {} {}".format(
                            len(frm_words),
                            " ".join(f"0x{w:08X}" for w in frm_words))
                        log.info("[NI-B] GBA NIReceiver ACKed state=%d → parent NI state=%d: %s",
                                 state, next_state, frm_msg)
                        self._ni_b_expect += 1  # arm for next ACK
                        self._enqueue_host_data(frm_msg, port)
                    else:
                        log.warning("[NI-B] GBA NIReceiver ACKed state=%d but no raw frame for state=%d",
                                    state, next_state)
                else:
                    # state=3 ACKed — NI handshake complete
                    self._in_ni_handshake = False
                    self._ni_b_expect = 0
                    log.info("[NI-B] GBA NIReceiver ACKed NI_END — NI complete, UNI can start")
            else:
                log.debug("[NI-B] GBA ack=1 state=%d ignored (ni_b_expect=%d)",
                          state, self._ni_b_expect)

    def on_ready(self, port: serial.Serial) -> None:
        """Called when RP2040 sends READY — dequeue and send one HOST_DATA.

        If the queue is empty the READY is remembered; the next enqueue
        will send immediately instead of queuing (handles the race where
        READY arrives before the Pi has produced its first HOST_DATA).
        """
        msg = None
        with self._hd_lock:
            try:
                msg = self._hd_queue.get_nowait()
            except queue.Empty:
                self._hd_ready_pending = True
        if msg is not None:
            _send(port, msg)

    def _enqueue_host_data(self, msg: str, port: serial.Serial) -> None:
        """Queue a HOST_DATA message; send immediately if READY is already pending."""
        send_now = False
        with self._hd_lock:
            if self._hd_ready_pending:
                self._hd_ready_pending = False
                send_now = True
            else:
                self._hd_queue.put(msg)
        if send_now:
            _send(port, msg)

    def reset(self) -> None:
        """Tear down any active join/session loop and return to IDLE.  Called on adapter reset."""
        self._sim_stop.set()   # signal the session loop to exit (outside the lock is fine for Event)
        with self._lock:
            self._teardown_locked()
            self._state = self.IDLE
        with self._hd_lock:
            self._hd_queue        = queue.SimpleQueue()
            self._hd_ready_pending = False
        self._in_ni_handshake      = False
        self._ni_b_expect          = 0
        self._pia_port             = None
        self._parent_ni_raw_frames = {}
        log.info("[CONN] reset")

    # ------------------------------------------------------------------
    # Background join thread
    # ------------------------------------------------------------------

    def _do_join(self, rfu_id: int, comm_id: "int | None",
                app_data: "bytes | None", rfutgt: "bytes | None",
                port: serial.Serial) -> None:
        # Phase 1: LDN join.  Failure here sends CONN_FAILED.
        try:
            transport = LiveTransport(
                keys_path=self._keys_path,
                phyname=self._phyname,
                ifname="ldnclient",
                local_comm_id=comm_id,       # None → LiveTransport picks first FRLG match
                log=log.debug,
            )
            transport.start(timeout=30, attempts=3)

            # Derive a 16-bit client ID from our LDN MAC (bytes 4-5, big-endian).
            # The GBA's librfu uses this as our adapter identity for the session.
            our_mac  = transport.our_mac or b"\x00\x00\x00\x00\x00\x01"
            our_id   = (our_mac[4] << 8 | our_mac[5]) & 0xFFFF or 0x0001
            # clientNum: GBA wireless adapter slot numbers are 0-based.  The
            # first (and only) child in a 2-player FRLG trade is slot 0.
            # The 0x20 IsConnectionComplete response is (clientNum << 16) | our_id;
            # the GBA detects "still connecting" via the exact sentinel 0x01000000,
            # NOT via a zero clientNum byte, so client_num=0 is valid and yields slot 0.
            client_num = 0

            with self._lock:
                self._transport = transport
                self._state     = self.COMPLETE

            log.info("[CONN] join SUCCESS rfu_id=0x%04x our_id=0x%04x clientNum=%d",
                     rfu_id, our_id, client_num)
            _send(port, f"CONN_COMPLETE {client_num} 0x{our_id:04x}")

        except Exception as e:
            reason = str(e).splitlines()[0][:80]
            with self._lock:
                self._state = self.FAILED
            log.error("[CONN] join FAILED rfu_id=0x%04x: %s", rfu_id, reason)
            _send(port, f"CONN_FAILED {reason}")
            return   # do not proceed to Pia

        # Phase 2: Pia S0 connection layer + data relay.
        # IMPORTANT: this runs OUTSIDE the try/except above.  Any exception here
        # must NOT send CONN_FAILED -- the RP2040 already received CONN_COMPLETE
        # and told the GBA the connection succeeded.  Sending CONN_FAILED now would
        # corrupt the RP2040 state machine (state flips COMPLETE → FAILED, causing
        # 0x21 to return 0x00000000 and the GBA to time out).
        try:
            self._run_pia(transport, port, rfutgt, client_num)
        except Exception as exc:
            log.error("[CONN] Pia S0 unexpected error (CONN_COMPLETE already sent): %s", exc)

    def _run_pia(self, transport: LiveTransport,
                port: serial.Serial, rfutgt: "bytes | None",
                client_num: int = 1) -> None:
        """Run the Pia S0 connection layer + UNI data relay loop via SwitchSession.

        - Net 0x11→0x12: Switch recognises us as a Pia peer.
        - Session join: Switch registers us as a participant.
        - RTT keepalive: keeps the session alive.
        - NI handshake: game-data exchange; once complete the Switch confirms
          JOIN_GROUP_OK — we forward JOIN_OK to the RP2040.
        - UNI: each non-idle host slot is packed and sent as HOST_DATA.

        Ticks at ~60 Hz until _sim_stop is set (by reset()).
        """
        import os as _os
        try:
            from frlgsim import crypto as cryptomod, pia_connect, linkplayer
        except ImportError as e:
            log.error("[CONN] Pia S0: missing dependency: %s — sync frlgsim to the Pi", e)
            return

        if not transport.ssid:
            log.error("[CONN] Pia S0: transport has no SSID; cannot initialise crypto")
            return

        # Build a LinkPlayer from the GBA's rfutgt record so the NI game-data
        # sub-frame carries the real trainer name and TID (not the "EMU" defaults).
        lp = linkplayer.LinkPlayer()    # defaults: name="EMU", version=LeafGreen
        if rfutgt is not None:
            try:
                r       = decode_record(rfutgt)
                name    = frlg_text(r["uname_bytes"]) or "GBA"
                tid     = r["player_tid"] & 0xFFFF
                # version field is only 3 bits in the rfutgt record; map to LP constant.
                ver_raw = r.get("version", 4) & 0x07
                if ver_raw == 5:
                    version = linkplayer.VERSION_LEAF_GREEN   # 0x4005
                else:
                    version = linkplayer.VERSION_FIRE_RED     # 0x4004 (default)
                lp = linkplayer.LinkPlayer(name=name, trainer_id=tid, version=version)
                log.info("[CONN] Pia NI: using GBA trainer %r TID=0x%04x version=0x%04x",
                         name, tid, version)
            except Exception as exc:
                log.warning("[CONN] Pia NI: could not decode rfutgt: %s — using defaults", exc)

        pc   = cryptomod.PiaCrypto(transport.ssid)
        conn = pia_connect.ConnectionManager(
            our_mac     = transport.our_mac  or b"\x00" * 6,
            host_mac    = transport.host_mac or b"\x00" * 6,
            our_ip      = transport.our_ip,
            host_ip     = transport.host_ip,
            player_name = lp.name,
            random4     = _os.urandom(4),
            log         = log.debug,
        )
        # Random nonzero 2-byte RFU connect id ('C' frame).  Any nonzero value
        # works; a fresh id per run avoids the host's ~40 s lost-id re-join lockout.
        raw_id     = int.from_bytes(_os.urandom(2), "big") or 1
        connect_id = raw_id.to_bytes(2, "big")

        session = SwitchSession(
            transport, pc, transport.our_ip, transport.host_ip,
            conn=conn, connect_id=connect_id, lp=lp, log=log.debug,
        )
        session.set_client_num(client_num)

        with self._lock:
            self._session = session

        period        = 1.0 / 59.727
        announced     = False
        join_notified = False
        self._pia_port = port   # expose port to set_gba_data() for NI ACK delivery
        log.info("[CONN] Pia S0: starting (Net 0x11 → Session join → NI handshake)...")

        try:
            while not self._sim_stop.is_set():
                try:
                    session.tick()
                except Exception as exc:
                    log.error("[CONN] Pia S0: tick() error: %s", exc)
                    break

                if session.connected and not announced:
                    announced = True
                    log.info("[CONN] Pia S0: CONNECTED — Switch should now show the join prompt")

                # NI join status: forward JOIN_OK (or disconnect on rejection) once.
                # join_status_pending fires only after ni_recv.complete (NI_END received),
                # so host_ni_bytes contains the full NI_START→NI_END LLSF byte sequence.
                if not join_notified and session.join_status_pending:
                    status = session.consume_join_status()
                    join_notified = True
                    if status == SwitchSession.JOIN_GROUP_OK:
                        # Parse individual sub-frames for Phase B (NIReceiver ACK
                        # cycle): when GBA ACKs state S we send raw frame S+1.
                        ni_bytes = session.host_ni_bytes
                        raw_frames: "dict[int, bytes]" = {}
                        off = 0
                        while off + 3 <= len(ni_bytes):
                            hdr       = int.from_bytes(ni_bytes[off:off + 3], "little")
                            frm_state = (hdr >> 14) & 0xF
                            frm_size  = hdr & 0x7F
                            raw_frames[frm_state] = bytes(ni_bytes[off:off + 3 + frm_size])
                            off += 3 + frm_size
                        self._parent_ni_raw_frames = raw_frames
                        log.info("[CONN] Switch JOIN_GROUP_OK — parsed %d parent NI raw frames: %s",
                                 len(raw_frames),
                                 {s: f.hex() for s, f in raw_frames.items()})
                        # No initial burst.  Phase A delivers each parent NI sub-frame
                        # combined with the PARENT LLSF ACK for that state (one per
                        # GBA NISender round).  This matches the real wireless adapter
                        # which always coalesces ACK + NI sub-frame in one 0x26 response.
                        self._client_num_cached = client_num
                        self._in_ni_handshake   = True
                    else:
                        log.warning("[CONN] Switch join rejected (status=%d) — disconnecting", status)
                        _send(port, "DISCONNECT")
                        break

                # Switch → GBA: forward UNI host slots as HOST_DATA.
                # Each slot is 14 raw bytes (gRecvCmds) from drain_host_slots().
                # We must prepend the 3-byte PARENT LLSF header before sending
                # so rfu_STC_CHILD_analyzeRecvPacket can parse it (same format as
                # the NI HOST_DATA: w0=byte_count, w1..=LLSF bytes packed LE).
                # n and phase are not preserved by gbaframe for UNI frames; 0 is
                # sufficient for FRLG 2-player (no multi-frame windowing needed).
                bm_slot  = 1 << client_num
                llsf_hdr = ((4 << 14) | (bm_slot << 18) | 14).to_bytes(3, "little")
                uni_slots = session.drain_host_slots()
                if not uni_slots and join_notified:
                    log.debug("[UNI] drain_host_slots() empty this tick")
                for slot_bytes in uni_slots:
                    if not join_notified or self._in_ni_handshake:
                        continue          # discard until GBA NI handshake is complete
                    uni_bytes = llsf_hdr + bytes(slot_bytes[:14])   # 17 bytes
                    words = [len(uni_bytes)]
                    for i in range(0, len(uni_bytes), 4):
                        words.append(int.from_bytes(
                            uni_bytes[i:i + 4].ljust(4, b"\x00"), "little"))
                    msg = "HOST_DATA {} {}".format(
                        len(words), " ".join(f"0x{w:08X}" for w in words))
                    log.info("[UNI] Switch→GBA slot: %s  raw=%s",
                             msg, slot_bytes[:14].hex())
                    self._enqueue_host_data(msg, port)

                # Clean disconnect signals.
                if session.ni_rejected or session.host_disconnected:
                    _send(port, "DISCONNECT")
                    break

                time.sleep(period)
        finally:
            self._in_ni_handshake = False
            self._pia_port        = None
            with self._lock:
                if self._session is session:
                    self._session = None
            log.info("[CONN] Pia S0: loop exited")

    # ------------------------------------------------------------------
    # Internal helpers (call with _lock held)
    # ------------------------------------------------------------------

    def _teardown_locked(self) -> None:
        """Stop any active LiveTransport.  Must be called with self._lock held."""
        self._session = None         # drop SwitchSession reference
        t = self._transport
        self._transport = None
        if t is not None:
            threading.Thread(target=t.stop, daemon=True, name="ldn-stop").start()


# ---------------------------------------------------------------------------
# Serial I/O helpers
# ---------------------------------------------------------------------------

def _send(port: serial.Serial, line: str) -> None:
    data = (line + "\n").encode("ascii", errors="replace")
    port.write(data)
    port.flush()
    log.debug("TX: %r", line)


def _broadcast_words_to_rfutgt(rfu_id: int, words: list[int]) -> bytes:
    """Reconstruct a 24-byte RFU beacon record from the 6 words the GBA sent
    in its 0x16 Broadcast command (w1-w6 of the BroadcastReadPoll format).

    The GBA's 0x16 Broadcast carries its own game identity without the metadata
    word (w0).  The layout of the 6 words (all LE u32):

      words[0]  =  serialNo(u16) | gname[0] | gname[1]
      words[1]  =  gname[2..5]
      words[2]  =  gname[6..9]
      words[3]  =  gname[10] | gname[11] | gname[12] | ~checksum
      words[4]  =  uname[0..3]
      words[5]  =  uname[4..7]

    We rebuild the 24-byte record used by rfu_advert_map.decode_record():

      [0x00:0x02]  player_tid    → gname[2:4]  (TID lives in gname bytes 2-3)
      [0x02:0x0A]  uname_bytes   → uname[0:8]
      [0x0A:0x0C]  rfu_id        → the host's rfu_id from the 0x1F Connect word
                                    (the field means "parent id child connects to")
      [0x0C:0x10]  partner_info  → gname[4:8]
      [0x10:0x14]  packed_game   → reconstructed from gname[0:2] (compat u16) +
                                    gname[8:12] fields
      [0x14:0x18]  trade_species → gname[8:10] packed word (species at bits 16-25)
    """
    # Unpack the 6 words into their constituent bytes (little-endian).
    raw = bytearray()
    for w in words:
        raw += w.to_bytes(4, "little")
    # raw[0:2]  = serialNo  (not stored in the 24-byte record)
    # raw[2:4]  = gname[0:2]  (compat u16)
    # raw[4:8]  = gname[2:6]
    # raw[8:12] = gname[6:10]
    # raw[12:15]= gname[10:13]
    # raw[15]   = ~checksum  (not needed for the record)
    # raw[16:20]= uname[0:4]
    # raw[20:24]= uname[4:8]
    gname  = bytes(raw[2:15])    # 13 bytes: raw[2] = gname[0] ... raw[14] = gname[12]
    uname  = bytes(raw[16:24])   # 8 bytes

    # 24-byte record layout (rfu_advert_map.py):
    #   [0x00:0x02] player_tid   = gname[2:4] (LE u16)
    #   [0x02:0x0A] uname_bytes  = uname[0:8]
    #   [0x0A:0x0C] rfu_id       = host rfu_id (LE u16)
    #   [0x0C:0x10] partner_info = gname[4:8]
    #   [0x10:0x14] packed_game  = reconstruct from gname[0:2] compat + gname[8:13]
    #   [0x14:0x18] trade_species_word = gname[8:12] repacked at bit 16
    record = bytearray(24)
    record[0x00:0x02] = gname[2:4]          # player_tid
    record[0x02:0x0A] = uname               # uname_bytes
    record[0x0A:0x0C] = rfu_id.to_bytes(2, "little")   # rfu_id (= host id)
    record[0x0C:0x10] = gname[4:8]          # partner_info
    # packed_game: copy the compat u16 (gname[0:2]) and the packed activity/
    # gender/version/etc. fields (gname[8:12]).  We don't have the full bitfield
    # expansion here; store what we have and let the host decode it.
    record[0x10:0x12] = gname[0:2]          # compat u16 (activity, version, language …)
    record[0x12:0x14] = gname[8:10]         # packed activity / tradeType bits
    record[0x14:0x18] = gname[8:12]         # trade_species_word
    return bytes(record)


def _rfutgt_to_words(record: bytes) -> list:
    """Convert a decoded RFU beacon record (24 bytes) to 7 LE u32 words
    in the GBA wireless adapter 0x1D BroadcastReadPoll per-host format (28 bytes).

    Field extraction is delegated to rfu_advert_map.decode_record(). See that
    module for the full beacon record layout and field descriptions.

    Fields not carried in the beacon (slot, mbootFlag) are zeroed.
    serialNo is hardcoded 0x0002 (FRLG).
    The gname checksum is computed: ~(sum(gname[0:8]) + sum(uname[0:8])) & 0xFF.
    """
    r = decode_record(record)

    uname = r["uname_bytes"]   # 8 GBA charmap bytes from record[0x02:0x0A]

    # Reconstruct compat u16 (GBA layout: language[0:4] | flags[4:10] | version[10:14])
    compat = ((r["language"]          & 0x0F)       |
              ((r["canLinkNationally"] & 0x01) << 7) |
              ((r["hasNationalDex"]    & 0x01) << 8) |
              ((r["gameClear"]         & 0x01) << 9) |
              ((r["version"]           & 0x0F) << 10))

    # Build gname (13 bytes, RfuGameData layout per ni.py / build_game_data)
    rgd = bytearray(13)
    rgd[0:2]  = (compat & 0xFFFF).to_bytes(2, "little")
    rgd[2:4]  = r["player_tid"].to_bytes(2, "little")
    rgd[4:8]  = r["partner_info"]
    rgd[8:10] = ((r["trade_species"] & 0x3FF) | ((r["tradeType"] & 0x3F) << 10)).to_bytes(2, "little")
    rgd[10]   = (r["activity"] & 0x7F) | ((r["startedActivity"] & 0x01) << 7)
    rgd[11]   = (r["playerGender"] & 0x01) | ((r["tradeLevel"] & 0x7F) << 1)
    rgd[12]   = 0

    checksum = (~(sum(rgd[0:8]) + sum(uname)) & 0xFF)

    # Assemble 28-byte 0x1D packet
    pkt = bytearray(28)
    pkt[0:2]   = r["rfu_id"].to_bytes(2, "little")
    pkt[2]     = 0              # slot (not carried)
    pkt[3]     = 0              # mbootFlag = 0
    pkt[4:6]   = b'\x02\x00'   # serialNo = 0x0002 (FRLG)
    pkt[6:19]  = rgd
    pkt[19]    = checksum
    pkt[20:28] = uname

    return [int.from_bytes(pkt[i * 4 : i * 4 + 4], "little") for i in range(7)]


def _send_hosts(port: serial.Serial, hosts: list) -> None:
    """Send a HOSTS/HOST response block for the given host list.

    Each host's rfutgt bytes (extracted from the LDN beacon's application_data)
    are converted to 7 GBA 0x1D words and sent to the RP2040.
    """
    _send(port, f"HOSTS {len(hosts)}")
    for slot, h in enumerate(hosts, start=1):
        gba_words = _rfutgt_to_words(h["rfutgt"])
        words_str = " ".join(f"0x{w:08x}" for w in gba_words)
        _send(port, f"HOST {words_str}")
        log.info("[RESULT] -> HOST slot=%d comm_id=0x%016x: %s",
                 slot, h["comm_id"], words_str)


# ---------------------------------------------------------------------------
# Main serial loop
# ---------------------------------------------------------------------------

def run(port_path: str, baud: int, phyname: str, keys_path: str) -> None:
    scanner   = ScanManager(phyname, keys_path)
    connector = ConnectManager(phyname, keys_path)

    log.info("Opening %s at %d baud", port_path, baud)
    with serial.Serial(port_path, baud, timeout=0.1) as port:
        log.info("Serial port open — waiting for commands from RP2040-Zero")
        buf = b""
        while True:
            chunk = port.read(256)
            if chunk:
                buf += chunk

            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                # Strip to printable ASCII only -- the RP2040 UART can emit a
                # couple of garbage bytes (\xff, \x00) at init before the first
                # real command arrives.  Filtering here means "SCAN_START" is
                # still recognised even if "\xff\x00" was prepended to it.
                clean = bytes(b for b in raw if 0x20 <= b <= 0x7E)
                line = clean.decode("ascii").strip()
                if not line:
                    continue

                log.debug("RX: %r", line)
                cmd = line.upper()

                if cmd == "SCAN_START":
                    # A new GBA session is starting -- tear down any leftover
                    # LDN connection from a previous session before scanning.
                    connector.reset()
                    scanner.start()

                elif cmd == "SCAN_RESULT":
                    hosts = scanner.get_hosts()
                    log.info("[RESULT] %d host(s) in cache", len(hosts))
                    try:
                        _send_hosts(port, hosts)
                    except serial.SerialException as e:
                        log.error("Serial write error: %s", e)

                elif cmd == "SCAN_STOP":
                    scanner.stop()

                elif line.upper().startswith("GBA_DATA "):
                    # "GBA_DATA N 0x<w0> 0x<w1> ..."
                    # GBA's 0x24/0x25 slot payload from the RP2040.  Route to the
                    # active relay engine so it can be forwarded to the Switch via
                    # Sim.tick() on the next Pia VBlank.
                    parts = line.split()
                    try:
                        count = int(parts[1], 10)
                        words = [int(w, 16) for w in parts[2 : 2 + count]]
                        log.info("[RELAY] GBA→Switch: %s", " ".join(f"0x{w:08X}" for w in words))
                        connector.set_gba_data(words)
                    except (IndexError, ValueError):
                        log.warning("[RELAY] malformed GBA_DATA: %r", line)

                elif line.strip().upper() == "READY":
                    # RP2040 signals it consumed the last HOST_DATA and is ready
                    # for the next one.  Dequeue and send (or set pending flag).
                    connector.on_ready(port)

                elif line.upper().startswith("CONNECT "):
                    # "CONNECT 0x<rfu_id> [w0 w1 w2 w3 w4 w5]"
                    # The 6 optional words are the GBA's 0x16 Broadcast identity
                    # (its own gname/uname) forwarded by the RP2040.
                    parts = line.split()
                    try:
                        rfu_id = int(parts[1], 16)
                    except (IndexError, ValueError):
                        log.warning("[CONN] malformed CONNECT line: %r", line)
                        _send(port, "CONN_FAILED bad rfu_id")
                    else:
                        broadcast_words = None
                        if len(parts) >= 8:
                            try:
                                broadcast_words = [int(w, 16) for w in parts[2:8]]
                            except ValueError:
                                log.warning("[CONN] malformed broadcast words in CONNECT: %r", line)
                        connector.connect(rfu_id, broadcast_words, scanner, port)

                else:
                    log.warning("Unknown command: %r", line)
                    _send(port, f"ERR unknown command {line!r}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Serial bridge between RP2040-Zero (GBA adapter) and LDN stack",
    )
    parser.add_argument(
        "--port", default="/dev/ttyAMA0",
        help="Serial port (default: /dev/ttyAMA0)",
    )
    parser.add_argument(
        "--baud", type=int, default=115200,
        help="Baud rate (default: 115200)",
    )
    parser.add_argument(
        "--phy", default="phy0",
        help="Wi-Fi phy for LDN scan (default: phy0)",
    )
    parser.add_argument(
        "--keys", default="~/.switch/prod.keys",
        help="Path to Switch prod.keys (default: ~/.switch/prod.keys)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable DEBUG logging",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    try:
        run(args.port, args.baud, args.phy, args.keys)
    except KeyboardInterrupt:
        log.info("Stopped.")
        sys.exit(0)
    except serial.SerialException as e:
        log.error("Serial error: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
