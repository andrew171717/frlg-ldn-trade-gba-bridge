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
               DISCONNECT_CLIENT <mask>\\n
                                   tear down the active client/session; mask uses
                                   zero-based clientNumber bits

Pi -> RP2040:  HOSTS <N>\n              (only in response to SCAN_RESULT)
               HOST <w0> ... <w6>\n      (N lines; 7 LE u32 words, GBA 0x1D format)
               ERR <msg>\n              on unexpected errors
               HD<N><w0>...<wN-1>\n  Raw parent NI/control data from the Switch.
                                       N words are packed as 8-char hex values (no spaces, no 0x).
                                       w0 is the LLSF byte count; remaining words contain LLSF bytes.
               UD8<w0>...<w7>\n       Compressed UNI data. Exactly 8 packed LE u32 words / 32 bytes:
                                       3-byte PARENT LLSF header + slot0 (14 bytes) + slot1
                                       (14 bytes) + one zero pad byte. The RP2040 expands this
                                       to the 73-byte, five-slot parent UNI frame.
               DISCONNECT\n            Switch rejected or cleanly disconnected

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
import sys
import threading
import time
from collections import deque

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
        # the next slot. Pi queues HOST_DATA strings and sends one per READY.
        # If READY arrives before anything is queued, hd_ready_pending is set so
        # the next enqueue sends immediately instead of queuing.
        #
        # _hd_inflight_msg is the message already handed to the RP2040 but not
        # yet consumed by the next READY. Native NI frames use it, together with
        # the queue tail, to collapse only consecutive retransmitted copies while
        # preserving distinct state/phase transitions in strict FIFO order.
        self._hd_queue: "deque[str]" = deque()
        self._hd_lock: threading.Lock = threading.Lock()
        self._hd_ready_pending: bool = False
        self._hd_inflight_msg: "str | None" = None
        # Recent child UNI slots are retained only for extraction verification.
        self._recent_gba_uni_slots: "list[bytes]" = []
        self._pia_port: "serial.Serial | None" = None

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
        """Forward one physical-GBA NI/UNI CHILD slot to the Switch unchanged.

        The RP2040's GBA_DATA words are the original 0x24/0x25 payload.
        SwitchSession removes only the adapter framing word and queues the exact
        CHILD LLSF bytes for the Pia Reliable 'T' stream.  LinkBridge does not
        synthesize NI acknowledgements or maintain a second NI state machine.
        """
        session = self._session
        if session is None:
            log.debug("[NATIVE] dropping GBA_DATA before SwitchSession exists")
            return

        try:
            raw = session.queue_gba_wire_words(words)
        except (TypeError, ValueError) as exc:
            log.warning("[NATIVE] malformed GBA_DATA ignored: %s; words=%s",
                        exc, " ".join(f"0x{int(w) & 0xFFFFFFFF:08X}" for w in words))
            return

        if not raw:
            log.debug("[NATIVE] GBA→Switch empty child slot")
            return

        child = int.from_bytes(raw[:2].ljust(2, b"\x00"), "little")
        state = (child >> 10) & 0x1F
        ack   = (child >> 9) & 1
        n     = (child >> 7) & 3
        phase = (child >> 5) & 3
        size  = child & 0x1F
        if state == 4 and len(raw) >= 16:
            self._recent_gba_uni_slots.append(raw[2:16])
            del self._recent_gba_uni_slots[:-8]
        log.info("[NATIVE] GBA→Switch state=%d ack=%d n=%d ph=%d size=%d raw=%s",
                 state, ack, n, phase, size, raw.hex())

    @staticmethod
    def _raw_host_frame_to_hd(raw: bytes) -> str:
        """Pack raw parent LLSF bytes into the existing HD wire format."""
        words = [len(raw)]
        for i in range(0, len(raw), 4):
            words.append(int.from_bytes(raw[i:i + 4].ljust(4, b"\x00"), "little"))
        return "HD{}{}".format(
            len(words), "".join(f"{word:08X}" for word in words)
        )

    def on_ready(self, port: serial.Serial) -> None:
        """Called when RP2040 sends READY — dequeue and send one HOST_DATA.

        READY means the previously delivered HOST_DATA has been consumed, so
        its in-flight de-duplication guard can be cleared. If the queue is empty,
        READY is remembered and the next enqueue is sent immediately.
        """
        msg = None
        with self._hd_lock:
            self._hd_inflight_msg = None
            if self._hd_queue:
                msg = self._hd_queue.popleft()
                self._hd_inflight_msg = msg
            else:
                self._hd_ready_pending = True
        if msg is not None:
            self._send_host_data(msg, port)

    def _enqueue_host_data(self, msg: str, port: serial.Serial,
                           *, collapse_consecutive: bool = False) -> bool:
        """Queue one HOST_DATA message and preserve FIFO protocol transitions.

        For native NI traffic, ``collapse_consecutive`` removes only repeated
        copies of the message currently in flight or directly at the queue tail.
        A distinct state/phase is always appended in order. Once READY consumes
        the current message, the same value may be queued again later, allowing
        genuine protocol retries without an unbounded duplicate backlog.

        Returns True when the message was sent or queued, False when it was
        collapsed as a consecutive duplicate.
        """
        send_now = False
        with self._hd_lock:
            if collapse_consecutive:
                if msg == self._hd_inflight_msg:
                    return False
                if self._hd_queue and self._hd_queue[-1] == msg:
                    return False

            if self._hd_ready_pending:
                self._hd_ready_pending = False
                self._hd_inflight_msg = msg
                send_now = True
            else:
                self._hd_queue.append(msg)

        if send_now:
            self._send_host_data(msg, port)
        return True

    def _send_host_data(self, msg: str, port: serial.Serial) -> None:
        """Write one queued parent RFU message to the RP2040."""
        _send(port, msg)

    def _forward_uni_slot(self, raw_slot: bytes,
                          log_label: str, port: serial.Serial) -> None:
        """Send the first two UNI slots in a fixed 32-byte UD8 message.

        UD8 is the first eight packed words of the final five-slot parent UNI
        frame: 3-byte PARENT LLSF header, 14-byte slot0, 14-byte slot1, and
        one zero byte that is also the first byte of empty slot2.
        """
        source = bytes(raw_slot)
        if len(source) < 3:
            log.warning("[UNI] %s: frame too short for PARENT LLSF (%d bytes)",
                        log_label, len(source))
            return

        llsf_int    = int.from_bytes(source[:3], "little")
        source_size = llsf_int & 0x1FF
        state       = (llsf_int >> 14) & 0x0F
        bm_slot     = (llsf_int >> 18) & 0x0F
        recv_first  = (llsf_int >> 22) & 0x03

        if state != 4:
            log.warning("[UNI] %s: refusing non-UNI frame state=%d", log_label, state)
            return
        if recv_first != 0:
            log.warning("[UNI] %s: recvFirst=%d; physical slot1 may not be client slot 0",
                        log_label, recv_first)

        # Parent layout is header[3], then contiguous 14-byte slots.
        slot0 = source[3:17].ljust(14, b"\x00")
        slot1 = source[17:31].ljust(14, b"\x00")

        # Advertise the complete five-slot server payload while transmitting
        # only the first two slots over UART.
        llsf_int = (llsf_int & ~0x1FF) | 70
        compressed = llsf_int.to_bytes(3, "little") + slot0 + slot1
        if len(compressed) != 31:
            raise AssertionError(
                f"compressed UNI prefix is {len(compressed)} bytes, expected 31"
            )

        packed = compressed + b"\x00"
        words = [int.from_bytes(packed[i:i + 4], "little")
                 for i in range(0, 32, 4)]
        msg = "UD8" + "".join(f"{w:08X}" for w in words)

        match_age = None
        for age, prior in enumerate(reversed(self._recent_gba_uni_slots)):
            if slot1 == prior:
                match_age = age
                break
        if match_age is None:
            slot1_check = ("unverified" if not self._recent_gba_uni_slots
                           else "NO RECENT GBA MATCH")
        else:
            slot1_check = f"matches GBA slot from {match_age} frame(s) ago"

        log.info(
            "[UNI] %s: %s state=%d size=%d→70 bmSlot=0x%X recvFirst=%d "
            "slot0=%s slot1=%s slot1Check=%s",
            log_label, msg, state, source_size, bm_slot, recv_first,
            slot0.hex(), slot1.hex(), slot1_check,
        )
        self._enqueue_host_data(msg, port)

    def reset(self) -> None:
        """Tear down any active join/session loop and return to IDLE.  Called on adapter reset."""
        self._sim_stop.set()   # signal the session loop to exit (outside the lock is fine for Event)
        with self._lock:
            self._teardown_locked()
            self._state = self.IDLE
        with self._hd_lock:
            self._hd_queue.clear()
            self._hd_ready_pending = False
            self._hd_inflight_msg = None
        self._pia_port             = None
        self._recent_gba_uni_slots = []
        log.info("[CONN] reset")

    # ------------------------------------------------------------------
    # Background join thread
    # ------------------------------------------------------------------

    def _do_join(self, rfu_id: int, comm_id: "int | None",
                app_data: "bytes | None", rfutgt: "bytes | None",
                port: serial.Serial) -> None:
        """Join LDN, establish Pia/RFU, then expose completion to the GBA.

        CONN_COMPLETE is deliberately delayed until the Switch accepts the
        emulator RFU connect ('A').  That synchronizes the physical GBA's NI
        start with the real Switch endpoint instead of starting a second, early
        synthetic NI handshake in LinkBridge.
        """
        try:
            transport = LiveTransport(
                keys_path=self._keys_path,
                phyname=self._phyname,
                ifname="ldnclient",
                local_comm_id=comm_id,
                log=log.debug,
            )
            transport.start(timeout=30, attempts=3)

            our_mac = transport.our_mac or b"\x00\x00\x00\x00\x00\x01"
            our_id = ((our_mac[4] << 8) | our_mac[5]) & 0xFFFF or 0x0001
            client_num = 0

            with self._lock:
                self._transport = transport
                # Stay PENDING until SwitchSession.rfu_ready.
                self._state = self.PENDING

            log.info(
                "[CONN] LDN join SUCCESS rfu_id=0x%04x our_id=0x%04x "
                "clientNum=%d — waiting for Pia/RFU accept",
                rfu_id, our_id, client_num,
            )

        except Exception as exc:
            reason = str(exc).splitlines()[0][:80]
            with self._lock:
                self._state = self.FAILED
            log.error("[CONN] join FAILED rfu_id=0x%04x: %s", rfu_id, reason)
            _send(port, f"CONN_FAILED {reason}")
            return

        try:
            self._run_pia(transport, port, rfutgt, client_num, our_id)
        except Exception as exc:
            reason = str(exc).splitlines()[0][:80]
            with self._lock:
                state = self._state
                if state == self.PENDING:
                    self._state = self.FAILED
            if state == self.PENDING and not self._sim_stop.is_set():
                log.error("[CONN] Pia/RFU setup FAILED before CONN_COMPLETE: %s", reason)
                _send(port, f"CONN_FAILED {reason}")
            else:
                log.error("[CONN] Pia session error after connection: %s", reason)

    def _run_pia(self, transport: LiveTransport,
                 port: serial.Serial, rfutgt: "bytes | None",
                 client_num: int, our_id: int) -> None:
        """Run Pia transport and relay native RFU slots in both directions.

        Sim still owns encryption, Pia Reliable, retransmission, K frames and
        connection traffic.  The physical GBA owns NI and UNI state: child slots
        are forwarded unchanged to the Switch, and parent slots are returned
        unchanged to the RP2040 (UNI keeps the existing UD8 UART compression).
        """
        import os as _os
        try:
            from frlgsim import crypto as cryptomod, pia_connect, linkplayer
        except ImportError as exc:
            raise RuntimeError(f"missing frlgsim dependency: {exc}") from exc

        if not transport.ssid:
            raise RuntimeError("transport has no SSID; cannot initialise Pia crypto")

        # Identity is still needed for the Pia/session metadata and LDN presence,
        # but no synthetic NI payload is generated from it in native mode.
        lp = linkplayer.LinkPlayer()
        if rfutgt is not None:
            try:
                record = decode_record(rfutgt)
                name = frlg_text(record["uname_bytes"]) or "GBA"
                tid = record["player_tid"] & 0xFFFF
                ver_raw = record.get("version", 4) & 0x07
                version = (linkplayer.VERSION_LEAF_GREEN if ver_raw == 5
                           else linkplayer.VERSION_FIRE_RED)
                lp = linkplayer.LinkPlayer(name=name, trainer_id=tid, version=version)
                log.info("[CONN] Pia identity: GBA trainer %r TID=0x%04x version=0x%04x",
                         name, tid, version)
            except Exception as exc:
                log.warning("[CONN] could not decode rfutgt identity: %s — using defaults", exc)

        pc = cryptomod.PiaCrypto(transport.ssid)
        conn = pia_connect.ConnectionManager(
            our_mac=transport.our_mac or b"\x00" * 6,
            host_mac=transport.host_mac or b"\x00" * 6,
            our_ip=transport.our_ip,
            host_ip=transport.host_ip,
            player_name=lp.name,
            random4=_os.urandom(4),
            log=log.debug,
        )
        raw_id = int.from_bytes(_os.urandom(2), "big") or 1
        connect_id = raw_id.to_bytes(2, "big")

        session = SwitchSession(
            transport, pc, transport.our_ip, transport.host_ip,
            conn=conn, connect_id=connect_id, lp=lp, log=log.debug,
        )
        session.set_client_num(client_num)

        with self._lock:
            self._session = session

        self._pia_port = port
        period = 1.0 / 59.727
        pia_announced = False
        completion_sent = False
        join_status_logged = False
        log.info("[CONN] Pia S0 starting; native GBA↔Switch NI relay armed")

        try:
            while not self._sim_stop.is_set():
                session.tick()

                if session.connected and not pia_announced:
                    pia_announced = True
                    log.info("[CONN] Pia S0 CONNECTED — waiting for Switch RFU accept ('A')")

                if session.rfu_ready and not completion_sent:
                    completion_sent = True
                    with self._lock:
                        self._state = self.COMPLETE
                    _send(port, f"CONN_COMPLETE {client_num} 0x{our_id:04x}")
                    log.info(
                        "[CONN] Switch RFU accepted — sent CONN_COMPLETE; "
                        "physical GBA now owns the native NI handshake"
                    )

                # Keep join-status parsing only as diagnostics.  The raw parent
                # status frame itself is forwarded to the physical GBA below.
                if session.join_status_pending and not join_status_logged:
                    status = session.consume_join_status()
                    join_status_logged = True
                    log.info("[NATIVE] observed Switch NI join status=%s; forwarded raw to GBA",
                             status)

                for frame in session.drain_frames():
                    raw = bytes(frame.get("raw_slot") or b"")
                    if not raw:
                        continue

                    state = frame.get("llsf_state")
                    if state == 4:
                        self._forward_uni_slot(raw, "Switch→GBA: NATIVE UNI", port)
                        continue

                    header = int.from_bytes(raw[:3].ljust(3, b"\x00"), "little")
                    size = header & 0x1FF
                    phase = (header >> 9) & 0x03
                    n = (header >> 11) & 0x03
                    ack = (header >> 13) & 0x01
                    ni_state = (header >> 14) & 0x0F
                    msg = self._raw_host_frame_to_hd(raw)
                    log.info(
                        "[NATIVE] Switch→GBA state=%d ack=%d n=%d ph=%d "
                        "size=%d raw=%s → %s",
                        ni_state, ack, n, phase, size, raw.hex(), msg,
                    )
                    # Parent NI is a current protocol level that may repeat each
                    # VBlank.  Replace stale unsent copies rather than building a
                    # queue the GBA can never drain.  A distinct next state cannot
                    # appear until the GBA's previous ACK reached the Switch.
                    queued = self._enqueue_host_data(
                        msg, port, collapse_consecutive=True
                    )
                    if not queued:
                        log.debug(
                            "[NATIVE] collapsed consecutive Switch→GBA frame "
                            "state=%d ack=%d n=%d ph=%d raw=%s",
                            ni_state, ack, n, phase, raw.hex(),
                        )

                if session.host_disconnected:
                    _send(port, "DISCONNECT")
                    break

                time.sleep(period)
        finally:
            self._pia_port = None
            with self._lock:
                if self._session is session:
                    self._session = None
            log.info("[CONN] Pia S0/native relay loop exited")

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

                elif cmd.startswith("DISCONNECT_CLIENT"):
                    parts = line.split()
                    try:
                        mask = int(parts[1], 0) & 0x0F if len(parts) > 1 else 0
                    except ValueError:
                        log.warning("[CONN] malformed DISCONNECT_CLIENT: %r", line)
                    else:
                        log.info("[CONN] GBA DisconnectClient mask=0x%X — tearing down session", mask)
                        connector.reset()
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
