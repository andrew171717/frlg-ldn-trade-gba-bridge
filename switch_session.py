"""switch_session.py — Manually-controlled Pia/LDN session with the Switch.

Unlike frlgsim.Sim (which drives the full trade bot automatically through
an autonomous 'engine'), this module gives linkbridge.py direct control:
you decide what comes in from the Switch and what goes out to it.

Architecture
------------
  RP2040 / GBA
       |
  linkbridge.py   (UART protocol — owns the RP2040 side)
       |
  SwitchSession   (this file — owns the Switch/Pia side)
       |
  Switch (Pia protocol over the LDN Wi-Fi link)

Typical loop (inside ConnectManager._run_pia or equivalent):
--------------------------------------------------------------
    session = SwitchSession(transport, pia_crypto, our_ip, host_ip,
                            conn=conn_mgr, connect_id=connect_id, lp=lp)

    period = 1.0 / 59.727          # one GBA VBlank
    while not stop_event.is_set():
        session.tick()

        # --- Switch → RP2040 ---
        if session.join_status_pending:
            status = session.consume_join_status()
            if status == SwitchSession.JOIN_GROUP_OK:
                send_to_rp2040("JOIN_OK")          # whatever the RP2040 expects
            else:
                send_to_rp2040(f"JOIN_FAIL {status}")

        for frame in session.drain_frames():
            # frame is a gbaframe.parse_in() dict; its "positional" list carries
            # the host's UNI slot bytes.  Extract and forward as needed:
            for mpid, slot_bytes in (frame.get("positional") or []):
                if mpid == 0:
                    send_host_slot_to_rp2040(slot_bytes)

        # --- RP2040 → Switch ---
        words = read_gba_words_from_rp2040()   # 7 u16s or 4 u32s, your choice
        session.set_gba_slot(words)

        time.sleep(period)

Key public interface
--------------------
tick()                    Drive one Pia VBlank.  Receives from Switch, runs
                          retransmit timers, sends the current GBA slot.
queue_gba_wire_words()    Queue one raw GBA wireless-adapter child slot from
                          a 0x24/0x25 payload for native forwarding.
drain_frames()            Return (and clear) all parsed UNI frames the Switch
                          sent since the last drain.  Each is a parse_in() dict.
join_status_pending       True exactly once: when the Switch's NI join status
                          has just arrived and hasn't been consumed yet.
consume_join_status()     Read and clear join_status_pending; returns the raw
                          int (5 = JOIN_GROUP_OK).  Call only when pending.

Key state properties
--------------------
connected                 S0 Pia handshake complete (Net + Session + RTT done).
join_ok                   True if the Switch returned JOIN_GROUP_OK (5).
ni_done                   True once both NI handshakes are done and UNI started.
host_disconnected         True if the Switch sent an emulator 'D' disconnect.
"""

import threading
from collections import deque

from frlgsim import gbaframe, rfu as _rfu
from frlgsim.sim import Sim

# PARENT LLSF state constants (from rfu.LCOM_*)
_LCOM_NULL     = 0
_LCOM_NI_START = 1

# Re-export so callers don't need to import ni directly.
JOIN_GROUP_OK = 5   # RFU_STATUS_JOIN_GROUP_OK — Switch accepted our join


# ---------------------------------------------------------------------------
# Internal engine adapter
# ---------------------------------------------------------------------------

class _PassthroughEngine:
    """Minimal Sim-compatible engine that queues data instead of acting on it.

    Sim calls:
      tick()            → returns the GBA's current 7-int slot to send as 'T'
      feed_in_frame()   → delivers a parsed Switch UNI/NI frame; we queue it
      poll_send_done()  → called when the send window is full; no-op here

    Sim reads via getattr:
      lp                → LinkPlayer for the NI game-data sub-frame
      in_seat_phase     → controls held-keys keepalive emission
      established       → same gate
      barrier           → if present, Sim sets barrier.max_emits
      _live             → if present, Sim gates READY_TO_TRADE on it
    """

    # Attributes Sim reads via getattr — set as class attrs so they are always
    # present without needing __init__ boilerplate.
    in_seat_phase = True   # keeps seat-phase NI/held-keys logic alive
    established   = False  # no automated hold-keys before we say so
    # Note: 'barrier' and '_live' are intentionally absent — Sim checks with
    # hasattr before touching them, and we don't want the automated trade FSM.

    def __init__(self) -> None:
        self._lock     = threading.Lock()
        self._slot     = [0] * 7    # legacy 7-u16 UNI slot interface
        self._raw_outgoing = deque() # exact CHILD LLSF slots waiting for the Switch
        self._incoming: list = []    # parsed Switch frames waiting to be drained

        # LinkPlayer for the NI sender in Sim._ensure_ni().  Set by SwitchSession
        # after construction (before the first tick that needs it).
        self.lp = None

        # Accumulated PARENT LLSF bytes from the Switch's host NI sub-frames.
        # Built here (not in Sim) so the accumulation stays bridge-specific.
        # Exposed via SwitchSession.host_ni_bytes for linkbridge.py → HOST_DATA.
        self._host_ni_frames = bytearray()
        self._host_ni_seen:  set = set()  # de-dup keys: state for NI_START, (state,n) for others
        # GBA child slot number (0-based, from CONN_COMPLETE).  Used to set
        # bmSlot in the reconstructed PARENT LLSF header (bmSlot = 1 << client_num).
        self._client_num: int = 0        # default: first (and only) child

    # -- called by SwitchSession (from the UART thread) ---------------------

    def set_gba_slot(self, words: list) -> None:
        """Store the legacy seven-u16 UNI command slot.  Thread-safe."""
        with self._lock:
            self._slot = list(words)

    def queue_raw_slot(self, slot: bytes) -> bool:
        """Queue one exact CHILD LLSF slot for native GBA→Switch relay.

        Collapse only when the same raw slot is already directly in front of
        this one at the queue tail. A matching slot is accepted again after the
        prior copy has been popped, so real GBA retries are still forwarded.

        Returns True when queued, False for an empty or consecutive duplicate
        slot.
        """
        raw = bytes(slot)
        if not raw:
            return False
        with self._lock:
            if self._raw_outgoing and self._raw_outgoing[-1] == raw:
                return False
            self._raw_outgoing.append(raw)
            return True

    def pop_raw_slot(self):
        """Pop the oldest exact CHILD LLSF slot, or None when no slot is ready."""
        with self._lock:
            if not self._raw_outgoing:
                return None
            return self._raw_outgoing.popleft()

    def drain(self) -> list:
        """Return and clear all queued incoming frames.  Thread-safe."""
        with self._lock:
            out = list(self._incoming)
            self._incoming.clear()
        return out

    # -- called by Sim (from the tick thread) --------------------------------

    def tick(self) -> list:
        """Return the GBA's current slot for Sim to wrap into a 'T' frame."""
        with self._lock:
            return list(self._slot)

    def feed_in_frame(self, rec) -> None:
        """Receive a parsed Switch frame.  Queue it for drain(), and accumulate NI bytes."""
        if rec is None:
            return
        # Accumulate PARENT LLSF bytes for bridge HOST_DATA relay.
        # Only host's own outgoing sub-frames: ack=0, state != NULL.
        # Reconstruct the 3-byte PARENT LLSF header from parsed fields.
        # recvFirst (bit 22) is set to 0 (not preserved by gbaframe.parse_in()).
        # bmSlot (bits 21-18): derived from _client_num; child slot n → bit (n-1).
        ni = rec.get("ni")
        if ni is not None and ni.get("ack") == 0:
            state = ni["state"]
            if state != _LCOM_NULL:
                bm_slot   = 1 << self._client_num
                llsf_int  = (state << 14) | (bm_slot << 18) | (ni["n"] << 11) | (ni["phase"] << 9) | ni["size"]
                slot_b    = llsf_int.to_bytes(3, "little") + bytes(ni["payload"])[:ni["size"]]
                # De-dup by (state, n) — each unique (state, n) pair is stored once.
                # NI_START retransmits increment n, so n=1 and n=2 are distinct entries.
                key = (state, ni["n"])
                with self._lock:
                    if key not in self._host_ni_seen:
                        self._host_ni_seen.add(key)
                        self._host_ni_frames.extend(slot_b)
        with self._lock:
            self._incoming.append(rec)

    def poll_send_done(self) -> None:
        """Called by Sim when the reliable send window is full.  Nothing to do."""


# ---------------------------------------------------------------------------
# Native GBA slot driver
# ---------------------------------------------------------------------------

class _NativeBridgeSim(Sim):
    """Use Sim's Pia/Reliable transport but never synthesize RFU NI/UNI slots.

    The physical GBA owns the librfu state machines.  Every child slot emitted
    by this class came directly from a GBA 0x24/0x25 payload.  Incoming parent
    slots are still parsed by Sim so its K acknowledgements and Reliable window
    remain intact, but Sim's synthetic NISender and NIReceiver ACK generator are
    bypassed completely.
    """

    def _gba_frame(self):
        self._emitted_ni_ack = None
        slot = self.engine.pop_raw_slot()
        if slot is None:
            return None

        parsed = _rfu.parse_llsf_child(slot) if len(slot) >= 2 else None
        if parsed is None:
            self.log(f"[NATIVE] GBA→Switch raw child slot ({len(slot)}B): {slot.hex()}")
        else:
            self.log(
                "[NATIVE] GBA→Switch child "
                f"state={parsed.get('state', '?')} ack={parsed.get('ack', '?')} "
                f"n={parsed.get('n', '?')} phase={parsed.get('phase', '?')} "
                f"size={parsed.get('size', '?')} raw={slot.hex()}"
            )
            if parsed.get('state') == 4:
                # Diagnostic compatibility for callers that inspect ni_done.
                self._ni_done = True

        return self._wrap_t(slot)


# ---------------------------------------------------------------------------
# Public session class
# ---------------------------------------------------------------------------

class SwitchSession:
    """Manual-control Pia session with the Switch.

    Wraps frlgsim.Sim but hands control of data flow back to the caller
    instead of delegating to an autonomous trade-bot engine.
    """

    JOIN_GROUP_OK = JOIN_GROUP_OK

    def __init__(self, transport, pia_crypto, our_ip: str, host_ip: str, *,
                 conn=None,
                 connect_id: "bytes | None" = None,
                 lp=None,
                 log=lambda *a: None) -> None:
        """
        Parameters
        ----------
        transport   : LiveTransport (already started).
        pia_crypto  : PiaCrypto built from the LDN session SSID.
        our_ip      : Our LDN IP (transport.our_ip).
        host_ip     : Host Switch LDN IP (transport.host_ip).
        conn        : ConnectionManager for the S0 Net/Session/RTT handshake.
        connect_id  : 2-byte emulator RFU connect id (any nonzero random bytes).
        lp          : LinkPlayer carrying GBA trainer name/TID for the NI frame.
        log         : Callable for debug logging (e.g. logging.getLogger(...).debug).
        """
        self.log = log

        self._engine     = _PassthroughEngine()
        self._engine.lp  = lp

        self._sim = _NativeBridgeSim(
            transport, pia_crypto, self._engine,
            our_ip, host_ip,
            conn=conn,
            connect_id=connect_id,
            log=log,
        )

        # join-status bookkeeping
        self._join_status_raw: "int | None" = None
        self._join_status_pending            = False   # True until consume_join_status() called

    def set_client_num(self, client_num: int) -> None:
        """Set the GBA's 1-based child slot number from CONN_COMPLETE.

        Must be called before the first NI frames arrive so the PARENT LLSF
        bmSlot field is reconstructed correctly in host_ni_bytes.
        """
        self._engine._client_num = client_num

    # ------------------------------------------------------------------
    # Main loop interface
    # ------------------------------------------------------------------

    def tick(self) -> None:
        """Drive one Pia VBlank (~16.7 ms).

        - Receives any datagrams the Switch sent and decrypts them.
        - Runs the S0 handshake (Net 0x11→0x12, Session join, RTT keepalive).
        - Drives the reliable sliding-window (retransmits, K-acks, bulk-ack).
        - Sends the GBA's current slot as a reliable 'T' frame to the Switch.

        Call in a tight loop at ~59.727 Hz with time.sleep(1/59.727) between
        calls, or let the caller pace it however it likes.
        """
        self._sim.tick()
        self._poll_join_status()

    def set_gba_slot(self, words: list) -> None:
        """Queue a legacy seven-u16 UNI command slot.

        Native LinkBridge code should call queue_gba_wire_words() so NI and UNI
        CHILD LLSF bytes are preserved exactly.  This method remains as a
        compatibility helper for callers that only have a 14-byte UNI command.
        """
        u16s = [(int(w) & 0xFFFF) for w in words[:7]]
        u16s += [0] * (7 - len(u16s))
        cmd14 = b"".join(v.to_bytes(2, "little") for v in u16s[:7])
        self._engine.queue_raw_slot(_rfu.uni_slot(cmd14))

    @staticmethod
    def decode_gba_wire_slot(u32_words: list) -> bytes:
        """Extract the exact CHILD LLSF slot from one GBA_DATA payload.

        The RP2040 forwards the wireless-adapter 0x24/0x25 payload unchanged:
        word 0 contains the RFU byte count in bits 8..15, while words 1..N
        contain the CHILD LLSF and payload packed little-endian.
        """
        if not u32_words:
            raise ValueError("empty GBA_DATA payload")

        header = int(u32_words[0]) & 0xFFFFFFFF
        slot_len = (header >> 8) & 0xFF
        packed = b"".join(
            (int(word) & 0xFFFFFFFF).to_bytes(4, "little")
            for word in u32_words[1:]
        )

        if slot_len == 0:
            return b""
        if slot_len > 16:
            raise ValueError(f"invalid CHILD slot length {slot_len}; maximum is 16")
        if slot_len > len(packed):
            raise ValueError(
                f"CHILD slot length {slot_len} exceeds {len(packed)} payload bytes"
            )
        return packed[:slot_len]

    def queue_gba_wire_words(self, u32_words: list) -> bytes:
        """Queue one exact NI or UNI CHILD slot from the RP2040.

        Returns the extracted raw slot for logging/tests. An empty slot is not
        queued. A slot identical to the current queue tail is collapsed; the
        same slot can be queued again after the prior copy has been popped.
        """
        raw = self.decode_gba_wire_slot(u32_words)
        if raw:
            self._engine.queue_raw_slot(raw)
        return raw

    def set_gba_words(self, u32_words: list) -> None:
        """Backward-compatible alias for queue_gba_wire_words()."""
        self.queue_gba_wire_words(u32_words)

    def drain_frames(self) -> list:
        """Return and clear all parsed Switch parent frames since the last call.

        Each element is a dict from gbaframe.parse_in():
          "type"       : frame type byte ('T', 'A', 'D', …)
          "ts"         : u32 timestamp from the Switch
          "llsf_state" : int (4 = UNI trade phase)
          "positional" : list of (mpId, 14-byte slot_bytes) tuples
                         mpId 0 is the host's own slot
          "ni"         : NI sub-frame dict if this is an NI frame, else absent

        Typical use to forward the host's slot to the RP2040:
            for frame in session.drain_frames():
                for mpid, slot_bytes in (frame.get("positional") or []):
                    if mpid == 0 and len(slot_bytes) >= 14:
                        forward_to_rp2040(slot_bytes)
        """
        return self._engine.drain()

    def drain_host_slots(self) -> list:
        """Return non-idle host slot bytes from UNI frames received since last call.

        Convenience wrapper over drain_frames() — filters to mpId=0 slots that
        have at least one nonzero byte (i.e. actual game data, not idle keepalives).
        Returns a list of bytes objects (each 14 bytes).

        Drains the same internal queue as drain_frames(); call one or the other
        per tick, not both.

        Typical use:
            for slot_bytes in session.drain_host_slots():
                u16s = [int.from_bytes(slot_bytes[i*2:i*2+2], "little") for i in range(7)]
                words = [u16s[0]|(u16s[1]<<16), u16s[2]|(u16s[3]<<16),
                         u16s[4]|(u16s[5]<<16), u16s[6]]
                words_str = " ".join(f"0x{w:08x}" for w in words)
                send_to_rp2040(f"HOST_DATA 4 {words_str}")
        """
        slots = []
        for frame in self.drain_frames():
            for mpid, slot_bytes in (frame.get("positional") or []):
                if mpid == 0 and len(slot_bytes) >= 14:
                    slots.append(bytes(slot_bytes[:14]))
        return slots

    # ------------------------------------------------------------------
    # Join-status handoff
    # ------------------------------------------------------------------

    @property
    def join_status_pending(self) -> bool:
        """True once the Switch's NI join status has arrived and not yet consumed.

        Poll this each tick, then call consume_join_status() to read the value
        and forward it to the RP2040:

            if session.join_status_pending:
                status = session.consume_join_status()
                if status == SwitchSession.JOIN_GROUP_OK:
                    send_to_rp2040("JOIN_OK")
        """
        return self._join_status_pending

    def consume_join_status(self) -> "int | None":
        """Read and clear the pending join status.

        Returns the raw status int (5 = JOIN_GROUP_OK) and clears
        join_status_pending.  Returns None if nothing is pending.
        """
        self._join_status_pending = False
        return self._join_status_raw

    # ------------------------------------------------------------------
    # State properties
    # ------------------------------------------------------------------

    @property
    def connected(self) -> bool:
        """True once the Pia S0 handshake (Net + Session + RTT) is complete."""
        return self._sim.connected

    @property
    def rfu_ready(self) -> bool:
        """True once the Switch accepted the emulator RFU connect ('A').

        LinkBridge must not tell the physical GBA that connection is complete
        before this point, or the GBA can begin NI before the Switch is ready.
        """
        return bool(self._sim._gba_accepted)

    @property
    def join_ok(self) -> bool:
        """True if the Switch returned JOIN_GROUP_OK (5) in its NI handshake."""
        return self._join_status_raw == JOIN_GROUP_OK

    @property
    def join_rejected(self) -> bool:
        """True if the Switch returned any non-OK join status (full/blacklist/etc)."""
        return self._join_status_raw is not None and self._join_status_raw != JOIN_GROUP_OK

    @property
    def ni_done(self) -> bool:
        """True once both NI handshakes are done and UNI slot exchange has begun."""
        return bool(self._sim._ni_done or self._sim._host_uni_seen)

    @property
    def host_ni_bytes(self) -> bytes:
        """Raw PARENT LLSF bytes of the Switch's host NI sub-frames (NI_START → NI_END).

        These are the exact bytes to pack into the RP2040's 0x26 (RECV_DATA) response
        so the GBA's rfu_STC_CHILD_analyzeRecvPacket processes them correctly:
          HOST_DATA N w0 w1 ...
        where w0 = len(host_ni_bytes) and w1..wN are the bytes packed as u32 LE.

        Only valid (complete) once join_status_pending is True (fired after NI_END).
        """
        return bytes(self._engine._host_ni_frames)

    @property
    def host_disconnected(self) -> bool:
        """True if the Switch sent an emulator 'D' (0x44) disconnect frame."""
        return self._sim.host_disconnected

    @property
    def ni_rejected(self) -> bool:
        """True if the Switch's NI join status was not JOIN_GROUP_OK."""
        return self._sim.ni_rejected

    @property
    def rx_count(self) -> int:
        """Number of datagrams successfully received from the Switch."""
        return self._sim.rx_count

    @property
    def tx_count(self) -> int:
        """Number of datagrams sent to the Switch."""
        return self._sim.tx_count

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _poll_join_status(self) -> None:
        """Check if the Switch's NI join status has arrived; fire pending flag once.

        Waits for ni_recv.complete (NI_END received) so that _engine._host_ni_frames
        contains the full NI byte sequence before linkbridge.py reads host_ni_bytes.
        """
        if self._join_status_raw is not None:
            return  # already captured
        st = self._sim._ni_recv.status
        # Gate on complete so _host_ni_frames includes NI_END before we signal.
        if st is not None and self._sim._ni_recv.complete:
            self._join_status_raw     = st
            self._join_status_pending = True
            label = "JOIN_GROUP_OK" if st == JOIN_GROUP_OK else f"REJECTED (status={st})"
            self.log(f"[switch_session] host NI join status = {label} "
                     f"({len(self._engine._host_ni_frames)} LLSF bytes collected)")
