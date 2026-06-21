"""The per-VBlank orchestrator - wires transport <-> crypto <-> Pia <-> FSM.

Two phases:
  S0 (connection): the ConnectionManager completes Net + Session(new) + RTT so the host
     registers us as a peer (this is what makes the "OK" prompt appear). Until then NO trade
     traffic is emitted.
  S1+ (trade): once connected, the TradeEngine's per-VBlank RFU slots ride Reliable(10).

Station VAR IDs are LEARNED from the wire (Pia header = [dst_var][src_var]; footer = dest var):
on each IN packet we record our id (= header dst) and the host's (= header src) and use them in
every OUT header/footer. Addressing: RTT -> broadcast, Net/Session/Reliable -> unicast to host.
A capture path mirrors every datagram to a .jsonl so it can be decrypted/analysed offline.
"""

import json
import os
import time

from . import crypto as cryptomod, reliable, gbaframe, rfu, pia_connect, ni, linkplayer

RELIABLE_SEQ_START = 0xFFF0

# Max Reliable messages packed into ONE Pia datagram (observed: the reference capture batches up to 9/datagram). We
# coalesce a VBlank's retransmits + K acks + the T slot + the ctrl-ack into one datagram (chunked at
# this size) instead of one datagram per frame - the prime BufferIsFull lever.
RELIABLE_BATCH_MAX = 9

# SEAT/LEAVE held-keys self-pacing (live fix: comms error on trade-room load). Ground-truthed
# against the reference capture: in the seat phase the working guest emits NEW held-keys at only ~8/s (NOT 1:1 with
# the host's ~20/s-unique / ~52/s-with-dupes T poll - it is self-paced, not clock-slaved) and leans
# on the reliable RETRANSMIT (a seq resent <=3x at ~117ms) to keep the wire alive across host gaps.
# Our old ~20/s free-running floor out-ran the host 2.6x; the window never drained -> a 67-seq
# retransmit storm filled the host's RFU buffer -> Communication error the instant we loaded in.
# 7 ticks @ 59.727Hz = ~117ms = ~8.5/s (matches the reference capture's 7.9/s new). SEAT_MAX_INFLIGHT keeps the
# concurrent unacked held-keys small (the reference capture held ~3-4 in flight) so a slow host can never build a storm.
SEAT_HELD_KEYS_PERIOD = 7
SEAT_MAX_INFLIGHT = 6

# LIVE-only cap on NEW standby (0x6600/0x5F00) frames emitted per count (live fix: standby flood
# deadlock). The reference capture sends each standby ~3-4x then stops; emitting every VBlank keeps the host
# in the same round forever (it sees continuous count=N) -> mutual deadlock + buffer flood. Bounding +
# reliable retransmit (live) matches the reference capture. Offline keeps the unbounded cadence its MockHost depends on.
BARRIER_EMITS = 6

# Pia reliable retransmit. The RTO is now ADAPTIVE in ReliableLink (SRTT-driven,
# clamp(1.5*srtt, RTO_FLOOR, RTO_CEIL)); RTX_TICKS is only the fallback until the first SRTT sample.
# RTO_FLOOR (~26 ticks=~440ms) keeps us from re-sending before an ack can return on the bridge; RTO_CEIL
# (~120 ticks=~2s) caps it at the worst observed RTT. The retransmit is GAP-TARGETED (RTX_GAP_LIMIT) in
# the high-volume block/trade phase; whole-window only for the tiny NI/seat phase (so the few critical
# NI frames get through). MAX_INFLIGHT=14: the reference capture's hard guest max was 18 / p99 12; the host receive credit
# may be a hard BufferIsFull limit, so err tighter, never larger (do NOT grow it to fill the high-RTT BDP).
RTX_TICKS = 7             # bootstrap RTO (ticks) until the first clean SRTT sample seeds rto(). (Tried
                          # 26 (~440ms) to break a suspected RTO death-spiral; reverted - it slowed
                          # recovery without fixing the deadlock; the real bug was the RTT-liveness parse.)
RTX_GAP_LIMIT = 1          # block/trade phase: re-send only the gap (host buffers out-of-order)
RTX_GAP_LIMIT_NI = 2       # NI/seat phase: a slightly longer tail (a few critical frames), still bounded
# RTO bounds in ticks: the host's reliable window uses RTO = 33ms + 1.4*RTT
# with NO exponential backoff (the deadline is 1.4*RTT_ms + 33, re-armed to the same value on
# each resend). 33ms = 2 ticks = the floor (the same field doubles as the ack timer). ReliableLink.rto() now
# mirrors this: floor + 1.4*srtt, no backoff (see reliable.py).
RTO_FLOOR = 2
# RTO_CEIL (live fix, measured: the 2s ceiling was tripping the host's 10s timeout). A dropped frame on the
# lossy bridge backed off (x1.25/resend) to the old 120-tick (~2s) ceiling, so recovery of one loss took
# 2s/retry and a multi-loss run stalled ~14s -> Communication error. The host NACKs the exact hole via its
# selective-ack MASK (non-zero on the live link, unlike the reference capture's clean dump), so the confirmed gap is now
# FAST-RETRANSMITTED at ~SRTT (ReliableLink, mask-driven) and this ceil is only a backstop for not-yet-NACKed
# frames - keep it tight (40 ticks ~= 670ms) so even the backstop path recovers well under the 10s timeout.
RTO_CEIL = 40
# MAX_INFLIGHT (Pia's ReliableSlidingWindow). The host's RECEIVE
# window is a HARD CREDIT of 6 (primary stream) / 8 (secondary), and on overflow it REFUSES the frame and does
# NOT ack it (Result 0x4c0d; the recv-insert only sets the received-flag on the successful store path -
# there is NO optimistic-mask-then-drop). So EXCEEDING the host's receive window is the real deadlock cause:
# our old 10/16 sent past the credit -> refused, un-acked frames -> stall/wedge (NOT bufferbloat eviction; the
# harness modeled that wrong). Size in-flight AT or UNDER the host credit: 6 (use the smaller/primary, safe vs
# the inferred instance mapping). The native-Pia reference capture ran in-flight median 3 / p90 7, consistent. Never grow past 6 - the
# host simply drops the excess. (Corollary: sack_free is SAFE per the RE - the host never masks a frame it
# didn't buffer - but it's MOOT at window=credit, since a gap fills the host's window and it refuses new frames
# until the gap delivers; so the lever is fast gap recovery + not exceeding the credit, not sack_free.)
MAX_INFLIGHT = 6
# K-ack pacing (validated). K-acks ride the SAME reliable window as block/T frames. Gating them on the
# FULL window let a host-T burst queue K-first and STARVE the block DATA (block phase crawl); reserving slots
# for data (old K_WINDOW=7) instead STARVED the K-acks the host needs to advance its OWN block-send (deadlock).
# The validated winner CAPS new K at ~5/VBlank: plenty to ack the host's ~0.6 frames/VBlank (no host re-INIT) yet
# it leaves window slots for the block fragment so DATA flows alongside. K_BACKLOG_MAX bounds the deferred-K
# backlog (K is a monotonic ts ack; the host re-sends un-acked T, so dropping the oldest deferred K is safe).
K_PER_VBLANK = 3           # max NEW K-acks/VBlank: leave slots for the block 'T' in the lean 6-frame window
                           # (host frame rate ~0.6/VBlank, so 3 is ample headroom and rarely binds)
K_WINDOW = 7               # DEPRECATED (K now caps at K_PER_VBLANK, gated by the full window)
K_BACKLOG_MAX = 32         # deferred-K backlog cap
ACK_PERIOD = 7             # ack cadence floor = ~117ms (7 ticks) ~= 8.5/s, MATCHING the real client. The
                           # 33ms in the RE is the host's delayed-ack CEILING (max wait), not its rate; the
                           # real client (the reference captures) emits ~8 ack-datagrams/s, ~95% of them PIGGYBACKED on a
                           # data datagram. We were emitting a STANDALONE pure-ack datagram ~every 33ms (~30/s,
                           # 95% of our OUT datagrams) -> on the half-duplex bridge that flooded our transmit
                           # side, collapsed the host->us return to ~9/s, and inflated send->ack RTT to 1.8s
                           # (real client: 24ms, SAME bridge) -> the 6-frame send window could push only ~3/s
                           # -> the party block crawled (~1.2 frag/s) and never completed. Ack at ~8.5/s,
                           # piggybacked when we're already sending data, standalone only when one is owed/at a gap.
COMPRESS_MIN = 62          # zstd-compress an OUT datagram iff its message body is >= this many bytes - the
                           # EXACT rule the real Switch host uses (measured across the reference captures IN: largest raw=61,
                           # smallest compressed=62, zero overlap = a clean size threshold). Below it, frames
                           # go raw. Combined with crypto.ZSTD_LEVEL=4 this makes our wire BYTE-IDENTICAL to a
                           # real FRLG joiner. Small frames (single gba slot / ack ~16-37B) stay raw as on HW.

# The child 'T' timestamp (body[0:4], u32 LE) is a per-NEW-frame counter that must INCREASE per new
# frame and be REUSED on a Pia retransmit. The reference capture's child seeded it ~0x362e; the host
# appears to gate on monotonicity + rate, not an absolute base (uncertain on the live link), so we seed nonzero.
TS_SEED = 0x0000362E


class Sim:
    def __init__(self, transport, pia_crypto, engine, our_ip, host_ip, *, conn=None,
                 our_var=0xc493, compress=False, header_flags=0x50, capture_path=None,
                 linkstate=None, parent_pid=None, log=lambda *a: None):
        self.t = transport
        self.crypto = pia_crypto
        self.engine = engine
        # Held-keys overworld link-state engine [frlgsim/linkstate.py]. When present, the sim emits a
        # 0xBE00 SEND_HELD_KEYS keepalive on an idle VBlank ONLY while engine.in_seat_phase (the
        # overworld/cable-seat phase, entry P0..P3) - mirroring SendKeysToRfu, which the real child
        # runs ONLY while gRfu.callback == SendKeysToRfu [link_rfu_2.c:1069-1080,1089]. That callback
        # is cleared the instant we warp out of the cable seat (Task_StartWirelessTrade case 0
        # ClearLinkRfuCallback() -> gRfu.callback = NULL [cable_club.c:918]), BEFORE the trade menu's
        # party exchange (BufferTradeParties [trade.c:935]) and the later gMain.callback1 =
        # CB1_UpdateLink swap [trade.c:1085]. So from the party exchange (S4) through the trade FSM and
        # the post-trade save an idle VBlank is a bare all-zero idle slot, NOT 0xBE00; held keys are
        # only re-armed back in the overworld field [field_fadetransition.c:226]. Held keys NEVER
        # override a real SEND_BLOCK/LINKCMD slot (we ask the engine first; held keys take an IDLE slot
        # only) - and engine.in_seat_phase latches off at the party exchange (entry.seat_phase_over).
        self.linkstate = linkstate
        self.conn = conn                # ConnectionManager (None = trade-only, e.g. replay)
        # LIVE (conn present): bound the engine's barrier standby burst per count so a never-completing
        # round can't flood the host (offline keeps the every-VBlank cadence its MockHost timing needs).
        if conn is not None and hasattr(engine, "barrier"):
            engine.barrier.max_emits = BARRIER_EMITS
        # LIVE: gate READY_TO_TRADE on the FULL BufferTradeParties (ribbons/settle) so we don't send it
        # mid-exchange (the offline MockHost model has no mail/ribbons, so this stays off there).
        if conn is not None and hasattr(engine, "_live"):
            engine._live = True
        self.our_ip = our_ip
        self.host_ip = host_ip
        self.broadcast = host_ip.rsplit(".", 1)[0] + ".255"
        self.compress = compress
        self.header_flags = header_flags
        self.log = log
        self.info = getattr(log, "info", log)   # clean milestone sink (default-mode narration)

        self.slot = rfu.SlotBuilder()
        # child 'T' frame counter (u32). One per NEW 'T' we emit; reused on a Pia retransmit (the
        # retransmit re-offers the already-built frame bytes, so ts is baked in at build time).
        self.ts = TS_SEED
        # gba-app 'K' ack layer: the host sends a 'T' per VBlank; we owe exactly ONE 'K' per
        # UNIQUE host 'T' ts (k_seq global +1 from 1; host idle T (slot_len<=1) is acked too; the host
        # sends us NO K). `mid` (1-based position within the OUT Pia datagram) is assigned at flush.
        self._k_seq = 0                  # last k_seq used (next K is _k_seq+1)
        self._acked_ts = set()           # host T ts values already K-acked (dedup)
        self._pending_k = []             # [(k_seq, acked_ts)] queued, awaiting a datagram flush
        # NI sender machine: after the host accepts our 'C' (the 'A' frame), the child
        # runs the librfu NI sender to deliver its RfuGameData before any UNI trade traffic. Built
        # lazily once we know our identity (from the engine's LinkPlayer); None until the NI phase.
        self._ni = None
        self._ni_done = False
        self._ni_built = False
        # RECV-side NI: right after the host acks OUR send-NI it runs its OWN librfu NI
        # sender (its connection/join-status data). The child must ACK every host NI sub-frame (ack=1,
        # mirroring state/n/phase) or the host's NI transfer never completes and the host faults the
        # link ("Communication error"). We DISCARD the host's NI data content (no reassembly needed).
        self._ni_recv = ni.NIReceiver()
        # recv-NI is CLOCK-SLAVED too: we hold the ack for the host's CURRENT NI sub-frame and re-emit
        # it once per host slot (credit) until the host advances (which updates it) - NOT a growing queue.
        # An append-per-host-frame queue spammed hundreds of duplicate acks when the host re-sent a
        # sub-frame under loss (observed: out NI_END x125); a single current-ack stays 1:1 with host slots.
        self._cur_ni_ack = None          # slot bytes for the latest host NI sub-frame's recv-ACK
        self._host_uni_seen = False      # host sent its first UNI slot (state 4) => its NI is done -> UNI
        # recv-NI must go QUIET at the host's NI NULL (observed Communication-error). The host re-sends
        # NI_END until it sees our ack, THEN sends NULL; after NULL there is a ~2.4s join-textbox gap
        # before UNI where the reference capture sends ZERO 'T'. We were re-emitting the stale NI_END ack right through
        # that gap -> a malformed/out-of-protocol slot -> in-game "Communication error". Stop acking at
        # NULL: emit _cur_ni_ack only until NULL is seen, then K/bulk-acks only until _host_uni_seen.
        self._host_ni_null_seen = False
        self._ni_status_logged = False    # logged the host's recv-NI join status once
        self.ni_rejected = False          # host returned a non-JOIN_GROUP_OK status -> abort the trade
        self.host_disconnected = False    # host sent a gba-app 'D' (0x44) disconnect -> link closing
        self.out_seq = RELIABLE_SEQ_START
        # Pia packet id: PER-CHANNEL counters keyed by Pia-header dst var-id (observed: the reference capture keeps THREE
        # independent pktid counters - dst=0x0000 establishing, dst=0x0001 session/RTT (1..960), dst=
        # host-var reliable/data (1..4415)). A single global counter SKIPPED reliable pktids once RTT/
        # Session interleaved, risking host-side drop/reorder of our reliable frames -> under-ack ->
        # BufferIsFull. Each channel starts at 1 and skips 0 on rollover; establishing frames force 0.
        self._pktid_by_dst = {}
        self.last_in_seq = 0
        self._recv_hi = None              # highest host reliable seq seen (wrap-aware) for the cumulative ack
        # Pia RELIABLE sliding-window connection (the reference capture, seq15+). The host ignores reliable DATA until
        # we OPEN the stream with an Initialized frame (the metadata/title frame); the two sides then
        # bulk-ACK each other. ReliableLink does the RETRANSMISSION (frames drop on this radio) +
        # in-order delivery. Live only (conn!=None); offline replay/tests keep the bare-gba path.
        # max_inflight ~20 (the reference capture's hard ceiling 18) so OUR send window never out-runs what it sustains.
        # rtx_ticks=RTX_TICKS with GAP-TARGETED retransmit (RTX_GAP_LIMIT, in _drive_reliable): re-send
        # only the oldest unacked frame, not the whole window - the host buffers out-of-order, so the gap
        # alone drains its run. This kills the high-RTT Go-Back-N flood that re-sent every frame many times
        # before its ack on the ~440ms-2s-RTT bridge (live fix: party transfer flooded ~4x / choked).
        self.rel = reliable.ReliableLink(start=RELIABLE_SEQ_START, max_inflight=MAX_INFLIGHT,
                                         rtx_ticks=RTX_TICKS, rto_floor=RTO_FLOOR, rto_ceil=RTO_CEIL)
        self._rel_opened = False
        self._ack_owed = False           # received host reliable DATA we haven't bulk-acked yet
        self._last_ack_tick = -100       # last tick we emitted a ctrl bulk-ack (steady-cadence floor)
        self._tick = 0                   # VBlank counter, drives the retransmit timers
        # gba-app RFU connect ('C') frame: the parent's RFU id (2 bytes), LEARNED from the host's
        # search beacon (transport.app_data) - NEVER guessed. None => we don't yet know it, so we
        # do NOT send a 'C' frame (the host stays in the bulk-ack-only state until we supply it).
        self._parent_pid = bytes(parent_pid) if parent_pid else None
        self._gba_conn_sent = False
        self._gba_accepted = False        # have we seen the host's gba-app connect accept ('A')
        # CLOCK-SLAVE (avoids the BufferIsFull / NI-flood): the child RFU link is a clock-SLAVE - it emits
        # exactly ONE slot per host slot it receives, NOT one per local VBlank, in EVERY phase (send-NI,
        # recv-NI, UNI). The reference capture's real guest sent 'T' at ~21/s (the host's slot rate); our old timer-driven
        # 60/s flooded the half-duplex wireless, contending with the host's transmit slots -> dropped host
        # frames + blocked the host's retransmits. In UNI that overflowed the host's reliable send buffer
        # (BufferIsFull); in the NI handshake it pushed OUR retransmit ratio to 71% (reference capture: 23%) so the NI
        # never converged and the host faulted ("Communication error"). _slot_credit counts host slots
        # delivered (in-order) but not yet responded to; _drive_reliable emits that many child slots.
        # During a receive gap, delivery stalls -> credit stops -> we go QUIET (like the real guest),
        # clearing the channel so the host's retransmit of the missing frame gets through.
        self._slot_credit = 0
        self._last_seat_emit = -100      # last tick we emitted a seat/leave held-keys (keepalive floor)
        self._seen_in = set()
        self.rx_count = self.tx_count = 0
        self.rx_fail = 0                 # host datagrams that failed to decrypt (SSID/key mismatch)
        self.rx_protos = {}              # proto id -> count of IN Pia messages seen
        self._dbg = None                 # set to a list to capture per-VBlank block-send emission decisions

        # our var id is SELF-CHOSEN and announced; the host's is LEARNED from incoming headers
        # (the host's first packet has dst=0 until it knows ours, so only src is reliable).
        self.our_var = our_var.to_bytes(2, "big")
        self.host_var = reliable.STATION_HOST.to_bytes(2, "big")
        self._learned = False
        # keep the ConnectionManager's self-chosen var id in sync with ours (it stores an int)
        if conn is not None:
            conn.our_var = int.from_bytes(self.our_var, "big")

        self._cap = open(capture_path, "w", buffering=1) if capture_path else None
        if self._cap:
            self._cap.write(json.dumps({"rec": "meta", "event": "session", "kind": "sim",
                                        "ip": our_ip, "host": host_ip,
                                        "ssid_hex": pia_crypto.ssid.hex(),
                                        "broadcast": self.broadcast}) + "\n")
        self._t0 = None

    @property
    def connected(self):
        return self.conn is None or self.conn.connected

    # ---- capture -----------------------------------------------------------
    def _capture(self, direction, datagram, src, dst):
        if not self._cap:
            return
        if self._t0 is None:
            self._t0 = time.monotonic()
        self._cap.write(json.dumps({
            "rec": "pkt", "seq": self.rx_count + self.tx_count, "t": time.monotonic() - self._t0,
            "dir": direction, "proto": 17, "src": src, "dst": dst,
            "len": len(datagram), "hex": datagram.hex(),
        }) + "\n")

    # ---- RX ----------------------------------------------------------------
    def process_datagram(self, datagram, src_ip):
        if not cryptomod.is_pia(datagram):
            return False
        self._capture("in", datagram, f"{src_ip}:12345", f"{self.our_ip}:12345")
        hdr = cryptomod.PiaHeader.unpack(datagram)
        # Pia header is [dst_var][src_var]; the host announces its own var id as src.
        if not self._learned and hdr.src != 0:
            self.host_var = hdr.src.to_bytes(2, "big")
            self._learned = True
            if self.conn:
                self.conn.learn_ids(self.our_var, self.host_var)
        pt = self.crypto.decrypt(datagram, src_ip)
        if pt is None:
            self.rx_fail += 1
            if self.rx_fail <= 5:
                self.log(f"[sim] RX decrypt FAILED from {src_ip} hdr.src=0x{hdr.src:04x} "
                         f"(SSID/key mismatch?) - host msg never reaches the handshake")
            return False
        app, _ = cryptomod.decompress(pt)
        msgs, _, _ = reliable.parse_app(app)
        for m in msgs:
            self.rx_protos[m.proto] = self.rx_protos.get(m.proto, 0) + 1
        if self.rx_count < 8:
            self.log(f"[sim] RX ok from {src_ip}: protos={[m.proto for m in msgs]} "
                     f"(1=Net 3=RTT 10=Reliable 13=Session)")
        for m in msgs:
            if m.proto == reliable.PROTO_RELIABLE:
                rl = reliable.parse_reliable(m.payload)
                if rl is None:
                    continue
                if self.conn is None:                 # offline replay: feed frames as they arrive
                    self._note_in_seq(rl.seq)
                    if rl.flagsA & 0x01 and rl.payload[:1] == b"\x57":
                        self._on_gba_in(rl.payload)
                elif rl.flagsA & 0x01:                # live AppData: PROCESS AS IT ARRIVES (gba-app is
                    # order-tolerant - it reassembles blocks by fragment index and re-pulls), so we deliver
                    # each UNIQUE frame the instant it lands (never stall the synchronous RFU exchange on a
                    # gap). But the PIA ACK is now an HONEST selective-repeat ack: note_received tracks the
                    # CONTIGUOUS recv_next + the out-of-order set, and ack_payload carries a selective MASK so
                    # the host FAST-RETRANSMITS its drops. (Was: 'ack to the highest received'
                    # which lied about gaps -> host never re-sent them -> slow gba-app re-pull only.)
                    self._ack_owed = True
                    if rl.seq not in self._seen_in:
                        self._note_in_seq(rl.seq)
                        if rl.payload[:1] == b"\x57":
                            self._on_gba_in(rl.payload)
                    self.rel.note_received(rl.seq)       # contiguous recv_next + recv_ooo for the selective ack
                else:                                 # live FLAGSA_CTRL: host's bulk-ack of OUR sends
                    ackid, mask = reliable.parse_bulk_ack(rl.payload)
                    self.rel.on_ack(ackid, mask, tick=self._tick)   # frees buffer + seeds the SRTT estimator
            elif self.conn:
                self.conn.on_message(m.proto, m.payload)
        self.rx_count += 1
        return True

    def _on_gba_in(self, payload):
        """Dispatch one IN gba-app frame (host/parent) by type.
          'A' (0x41): the host's gba-app connect ACCEPT - the RFU link is up; arm the NI phase.
          'T' (0x54): a host slot frame. EVERY unique host T ts is K-acked (incl. idle slot_len<=1).
              UNI 'T' (the mpId rows) is fed to the trade engine; a host NI 'T' is the host's game-data
              handshake which our recv side must (eventually) ack - it is consumed here (its slots are
              not UNI, so the engine ignores them) and acked via the same per-ts K.
          'K' (0x4b): the host never sends us K, so this is informational only."""
        rec = gbaframe.parse_in(payload)
        if rec is None:
            return
        typ = rec.get("type")
        if typ == "A" and not self._gba_accepted:
            self._gba_accepted = True              # host's gba-app connect ACCEPT (0x41)
            self.log(f"[sim] host ACCEPTED gba-app connect ('A' 0x41): {payload[:10].hex()} "
                     f"-> parent pid is CORRECT; RFU link up, starting the NI handshake")
            self.info("Host accepted the link.")
            return
        if typ == gbaframe.TYPE_D and not self.host_disconnected:
            # host gba-app DISCONNECT ('D' 0x44): the RFU link is going down. Surface it (a clean leave
            # signal) instead of silently ignoring it and spinning on a dead link.
            self.host_disconnected = True
            self.log("[sim] host gba-app DISCONNECT ('D' 0x44) - RFU link closing")
            return
        if typ != "T":
            return
        # K-ack EVERY unique host T ts (one K per unique ts; host idle T is still acked).
        ts = rec.get("ts")
        if ts is not None and ts not in self._acked_ts:
            self._acked_ts.add(ts)
            self._k_seq += 1
            self._pending_k.append((self._k_seq, ts))
            if len(self._acked_ts) > 8192:         # bound memory on a long session
                self._acked_ts = set(list(self._acked_ts)[-2048:])
        # RECV-side NI: a host NI-window 'T' (NI_START/NI/NI_END/NULL, NOT UNI) carries record['ni'].
        # When it is the host's OWN outgoing NI (ack=0) enqueue a recv-NI ACK slot MIRRORING its
        # (state, n, phase) with ack=1, sz=0 (the host's NI data content is discarded). NIReceiver
        # marks the host's NI complete on the host NI_END (or NULL). This is ORTHOGONAL to the K layer
        # above (the host NI 'T' is still K-acked); the ack rides a SEPARATE child 'T' (see _gba_frame).
        ni_rec = rec.get("ni")
        if ni_rec is not None:
            ack_slot = self._ni_recv.on_host_ni(ni_rec)
            if ack_slot is not None:
                self._cur_ni_ack = ack_slot         # latest host NI sub-frame -> the ack to re-emit
            if ni_rec.get("state") == rfu.LCOM_NULL and ni_rec.get("ack") == 0:
                self._host_ni_null_seen = True       # host's NI terminator -> stop acking, go quiet
            # host join STATUS: log it once; a non-OK value means the host REJECTED us (full
            # lobby / blacklist / version mismatch), so flag it - else we'd ack forever then hang on a
            # UNI that never comes.
            st = self._ni_recv.status
            if st is not None and not self._ni_status_logged:
                self._ni_status_logged = True
                if st == ni.RFU_STATUS_JOIN_GROUP_OK:
                    self.log(f"[sim] host NI join status = JOIN_GROUP_OK ({st})")
                else:
                    self.ni_rejected = True
                    self.log(f"[sim] WARNING: host NI join status = {st} (NOT JOIN_GROUP_OK=5) -> host "
                             f"REJECTED our join; the trade cannot proceed")
        # The host's FIRST UNI slot (parent LLSF state 4) means its NI is finished and it has entered the
        # UNI trade phase -> our recv-NI is done. This is the transition trigger (it guarantees we never
        # send a UNI slot before the host itself is in UNI, which would fault its RFU link manager).
        if rec.get("llsf_state") == 4:
            self._host_uni_seen = True
        # CLOCK-SLAVE: EVERY host 'T' (NI sub-frame, NI ack, UNI, or idle keepalive) is one host SLOT =
        # one clock tick - owe exactly one child slot back (_drive_reliable emits _slot_credit of them,
        # the right slot for the current phase). This rate-matches our TX to the host in ALL phases
        # instead of the old free-running 60/s, and naturally goes quiet during a receive gap (no
        # in-order delivery -> no credit) so the host can retransmit. (NI frames previously skipped this,
        # so the NI phase still flooded at 60/s -> 71% retransmits -> host fault.)
        self._slot_credit += 1
        # Feed the host's UNI slots (the mpId gRecvCmds) to the trade engine; the parse_in record's
        # `positional` alias is exactly what the engine reads. A host idle/NI 'T' has no
        # UNI slots, so feed_in_frame is a no-op for it (it still got K-acked + counted as a tick).
        self.engine.feed_in_frame(rec)

    def _note_in_seq(self, seq):
        if seq in self._seen_in:
            return
        self._seen_in.add(seq)
        if len(self._seen_in) > 4096:
            self._seen_in = set(list(self._seen_in)[-1024:])
        if ((seq - self.last_in_seq) & 0xFFFF) < 0x8000:
            self.last_in_seq = seq

    # ---- TX ----------------------------------------------------------------
    def _next_pktid(self, dv):
        """Per-CHANNEL Pia packet id keyed by header dst var-id (observed: the reference capture keeps independent
        counters per dst - dst=0x0001 session/RTT (1..960), dst=host-var reliable/data (1..4415)).
        Each channel counts from 1, skipping 0 on rollover, so the reliable channel stays contiguous
        even when RTT/Session frames interleave on their own dst. The establishing connection-exchange
        frames (Net 0x12 / Session join) ride pktid 0 by passing pktid=0 explicitly to _send."""
        pktid = self._pktid_by_dst.get(dv, 1)
        self._pktid_by_dst[dv] = pktid + 1 if pktid < 0xFFFF else 1
        return pktid

    def _send_messages(self, messages, *, dst_var=None, src_var=None, compress=False,
                       footer=True, establishing=False, unicast=True, pktid=None, footer_var=None):
        """Frame N Pia messages into ONE datagram and send it (observed: the reference capture BATCHES up to 9 reliable
        messages per datagram; we used to emit one datagram per frame -> ~1.6x+ datagram flood ->
        host SEND-buffer overflow (BufferIsFull)]. `messages` = [(proto, payload), ...] sharing one
        header (same dst/src/pktid channel). The encrypted plaintext is:

            [ message* , optionally zstd-compressed AS A WHOLE ]
            [ footer: 2-byte recipient (destination) variable id, UNCOMPRESSED, only if footer ]
            [ 0xFF padding so the total is a multiple of 16 ]

        header byte5 = (padding_size << 4) | flags, flags = (1 if zstd) | (2 if establishing); the
        footer-size byte = len(footer). One pktid per datagram (per-channel), NOT per message."""
        if not messages:
            return None
        dv = dst_var if dst_var is not None else int.from_bytes(self.host_var, "big")
        sv = src_var if src_var is not None else int.from_bytes(self.our_var, "big")
        body = b"".join(reliable.build_message(m[0], m[1], m[2] if len(m) > 2 else None)
                        for m in messages)
        # zstd-compress like a real FRLG joiner: the host compresses iff the message body is >= 62 bytes
        # (COMPRESS_MIN), a pure size threshold. `compress=True` (the Session join) forces it regardless. At
        # crypto.ZSTD_LEVEL=4 + the window-frame header this is byte-identical to the console. Auto-compress
        # only when zstd is actually available (an explicit compress=True still raises if it isn't, as before).
        do_zstd = compress or (len(body) >= COMPRESS_MIN and cryptomod.HAVE_ZSTD)
        if do_zstd:
            body = cryptomod.compress(body)
        fsize = 0
        if footer:
            # footer = the RECIPIENT var id, which is usually the header dst, but for RTT the header dst
            # is the session pseudo-station 0x0001 while the recipient is still the host 0x7620.
            fv = footer_var if footer_var is not None else dv
            body += fv.to_bytes(2, "big")
            fsize = 2
        pad = (-len(body)) % 16                      # 0xFF-pad the whole body to a multiple of 16
        body += b"\xff" * pad
        flags = (1 if do_zstd else 0) | (2 if establishing else 0)
        if pktid is None:
            pktid = self._next_pktid(dv)
        hdr = cryptomod.PiaHeader(dst=dv, src=sv, pktid=pktid, nonce8=os.urandom(8),
                                  flags=(pad << 4) | flags, footer=fsize)
        dg = self.crypto.encrypt(body, self.our_ip, hdr)
        dst = self.host_ip if unicast else self.broadcast
        self.t.send(dg, dst)
        self._capture("out", dg, f"{self.our_ip}:12345", f"{dst}:12345")
        self.tx_count += 1
        return dg

    def _send(self, proto, payload, *, dst_var=None, src_var=None, compress=False,
              footer=True, establishing=False, unicast=True, pktid=None, footer_var=None):
        """Single-message convenience wrapper over _send_messages (one message per datagram) - used
        for the connection handshake / RTT / a lone reliable frame. The reliable STREAM batches via
        _send_messages directly (see _drive_reliable)."""
        return self._send_messages([(proto, payload)], dst_var=dst_var, src_var=src_var,
                                   compress=compress, footer=footer, establishing=establishing,
                                   unicast=unicast, pktid=pktid, footer_var=footer_var)

    # ---- Pia Reliable sliding-window connection -----------------------------
    def _tx_reliable(self, seq, flagsA, inner):
        """Wrap one inner payload in a Reliable(10) frame and send it. The header's "lowest pending
        ack" = our send-window left edge; pure-ack (FLAGSA_CTRL) frames carry no sequence id of
        their own, so they ride the window base seq (the reference capture reuses 0xFFF0)."""
        s = RELIABLE_SEQ_START if seq is None else seq
        rel = reliable.build_reliable(s, self.rel.send_low(), inner, flagsA=flagsA)
        self._send(reliable.PROTO_RELIABLE, rel,
                   dst_var=int.from_bytes(self.host_var, "big"),
                   src_var=int.from_bytes(self.our_var, "big"),
                   compress=False, footer=True, establishing=False)

    def _tx_reliable_batch(self, batch):
        """Send a list of reliable frames as FEW datagrams as possible (<=RELIABLE_BATCH_MAX messages
        each) (observed: the reference capture packs up to 9 Reliable messages per datagram - the prime BufferIsFull
        lever). `batch` = [(seq, flagsA, inner), ...] already in wire order (retransmits, K*, T,
        ctrl-ack). All ride the host channel (dst=host_var) so they share one per-channel pktid."""
        if not batch:
            return
        msgs = []
        for seq, flagsA, inner in batch:
            s = RELIABLE_SEQ_START if seq is None else seq
            rel = reliable.build_reliable(s, self.rel.send_low(), inner, flagsA=flagsA)
            # Pia MESSAGE-flags 0x40 on standalone acks. The native client AND the Switch host set 0x40 on
            # EVERY pure-ack (msgflags); we were the only party sending acks at msgflags=0. It's "unknown" in
            # kinnay's wiki but universal on acks - the host honored our CUMULATIVE ack at 0 (its window freed
            # early) yet never fast-retransmitted a hole, so 0x40 is almost certainly the bit that tells the
            # host to act on the ack's SELECTIVE mask (SACK / fast-retransmit). The ctrl-ack is LAST in the
            # batch so its 0x40 never leaks into a later message via msgflags inheritance. Data stays at 0.
            mf = 0x40 if flagsA == reliable.FLAGSA_CTRL else None
            msgs.append((reliable.PROTO_RELIABLE, rel, mf))
        dv = int.from_bytes(self.host_var, "big")
        sv = int.from_bytes(self.our_var, "big")
        for i in range(0, len(msgs), RELIABLE_BATCH_MAX):
            self._send_messages(msgs[i:i + RELIABLE_BATCH_MAX], dst_var=dv, src_var=sv,
                                compress=False, footer=True, establishing=False)

    def _drive_reliable(self):
        """Per-VBlank Reliable traffic once Pia-connected, loss-tolerant via ReliableLink:
          1. open the stream with the metadata frame (Initialized) - itself retransmitted until acked;
          2. RETRANSMIT any unacked frame whose timer expired (the dropped INIT/block/data frames);
          3. bulk-ack host data we've received (with a gap mask);
          4. send a new gba-app frame, unless the in-flight window is full (let retransmits drain).
        Without the open frame the host never starts its Reliable stream; without retransmission a
        single dropped frame stalls the whole stream (frames are known to drop)."""
        tick = self._tick
        if not self._rel_opened:
            seq = self.rel.queue(reliable.METADATA_FRAME, reliable.FLAGSA_INIT, tick)
            self._tx_reliable(seq, reliable.FLAGSA_INIT, reliable.METADATA_FRAME)
            self._rel_opened = True
            return                        # the reference capture opens with the metadata ('J') frame alone
        if self._parent_pid is not None and not self._gba_conn_sent:
            # gba-app RFU connection request ('C', rfu_REQ_startConnectParent) - the host won't send
            # its accept ('A') or start its slot ('T') stream until it sees this (the reference capture). We only
            # send it once we know the parent's RFU id (from the beacon); never with a guessed value.
            frame = gbaframe.build_connect(self._parent_pid)
            seq = self.rel.queue(frame, reliable.FLAGSA_GBA, tick)
            self._tx_reliable(seq, reliable.FLAGSA_GBA, frame)
            self._gba_conn_sent = True
            return
        # BATCH this VBlank's whole reliable output into ONE datagram (observed: the reference capture packs up to 9
        # messages/datagram; one-datagram-per-frame was the prime BufferIsFull cause). Wire order
        # (reference capture's dominant KT/KTA): retransmits, then new K* (mid 1..n), then the T slot, then the
        # ctrl-ack LAST. Everything shares the host channel so it rides one per-channel pktid.
        batch = []
        # 1. retransmits. BLOCK/TRADE phase: GAP-TARGETED (limit=RTX_GAP_LIMIT) - re-send only the oldest
        #    unacked frame (the cumulative gap); the host buffers out-of-order so delivering the gap drains
        #    its whole run. This kills the high-RTT Go-Back-N flood (re-sending the whole window on the
        #    ~440ms-2s-RTT bridge re-sent every frame many times before its ack -> flood -> latency climbs).
        #    NI/SEAT phase (low-volume, all frames critical): whole-window (limit=None, capped at the batch)
        #    so our few NI/standby frames get through fast - gap-targeting there starved the send-NI.
        #    due_retransmits returns the ORIGINAL bytes (a retransmitted K keeps its original mid).
        in_block_phase = self._gba_accepted and not getattr(self.engine, "in_seat_phase", True)
        rtx_limit = RTX_GAP_LIMIT if in_block_phase else RTX_GAP_LIMIT_NI   # never None
        for seq, flagsA, inner in self.rel.due_retransmits(tick, limit=rtx_limit)[:RELIABLE_BATCH_MAX]:
            batch.append((seq, flagsA, inner))
        # 2. new K acks - queue K (one per pending host T ts, mid = 1-based K-run index) up to the FULL send
        #    window, BEFORE our own data below (priority). K-acks are how the host's RFU block-send
        #    knows we received its fragments; starving them STALLS the host's block -> it re-INITs -> the
        #    LinkPlayer handshake DEADLOCKS (we re-stream ours, host re-INITs its). The old K_WINDOW=7 sub-gate
        #    reserved slots for DATA, but that's backwards - with MAX_INFLIGHT>7 our data filled inflight past
        #    7, K-acks were deferred and DROPPED (backlog cap), and only ~60% of host frames got K-acked. The
        #    working run had window 6 < 7 so K-acks were never gated. K-acks are MORE critical than new data
        #    (they unblock the peer), so gate them on the full window and let DATA take what's left; the host
        #    frame rate (~12-20/s) is well under our K-ack capacity (60/s) so they never crowd out our data.
        mid = 0
        queued = 0
        for k_seq, acked_ts in self._pending_k:
            if self.rel.inflight() >= self.rel.max_inflight or queued >= K_PER_VBLANK:
                break          # cap K at K_PER_VBLANK/VBlank -> leave window slots for the block 'T'
            mid += 1
            kf = gbaframe.build_k(k_seq, mid, acked_ts)
            seq = self.rel.queue(kf, reliable.FLAGSA_GBA, tick)
            batch.append((seq, reliable.FLAGSA_GBA, kf))
            queued += 1
        self._pending_k = self._pending_k[queued:][-K_BACKLOG_MAX:]
        # 3. our own gba 'T' slot(s) - ONLY after the host ACCEPTS our connect ('A'); the first post-'A'
        #    'T' must be the NI_START (a UNI slot before NI faults the host RFU link manager). CLOCK-SLAVE:
        #    one child slot per host slot delivered (credit), bounded by the send window; _gba_frame
        #    returns the phase-correct slot or None (recv-NI waiting -> credit consumed, nothing emitted).
        if self._gba_accepted:
            # ONE gba slot per VBlank, on OUR OWN clock, window-bounded. (Root-cause fix, measured.) The
            # RFU child enqueues exactly one slot per VBlank (link_rfu_2.c:1003) off its OWN RfuVSync - it
            # is NOT clocked by when the host's poll datagram arrives over the network. The reference capture's working
            # guest sends OUT every ~15ms (one/VBlank, 32/s sustained, in bursts). We had THREE different
            # cadences here - seat held-keys (one/VBlank), block STREAM (window-fill burst), and a catch-all
            # else gated on _slot_credit (host-poll ARRIVAL) - and the catch-all is where the trade phase
            # actually lives, so over the ~90ms-RTT bridge it throttled OUT to the round-trip rate (~10/s,
            # 118ms gaps), starving the whole synchronous exchange (host then sat idle waiting for us, IN
            # collapsed to 10.8/s). _gba_frame() already returns the phase-correct slot (NI sub-frame,
            # held-keys keepalive, block fragment, warp standby, or idle keepalive) or None (recv-NI quiet /
            # nothing to send), so ONE call per VBlank is correct for every phase. The flood guard is the
            # send window (max_inflight) + adaptive-RTO gap-targeted retransmit, NOT response pacing; one
            # slot/VBlank can't burst the host's receive buffer the way a window-fill can (BufferIsFull),
            # and over high RTT it naturally keeps ~RTT/VBlank slots in flight (well under the window).
            self._slot_credit = 0
            _inflight_gate = self.rel.inflight()
            _gated = _inflight_gate >= self.rel.max_inflight
            inner = None
            if not _gated:
                inner = self._gba_frame()
                if inner is not None:
                    self._last_seat_emit = tick
                    seq = self.rel.queue(inner, reliable.FLAGSA_GBA, tick)
                    batch.append((seq, reliable.FLAGSA_GBA, inner))
            else:
                # WINDOW-GATED: we cannot EMIT a new slot, but an in-flight block send must still
                # advance HOLD -> DONE on the host's reflection (which arrives via IN frames, not our
                # send-window). Gating the sender's STATE here was the 2/3 party-block deadlock: under
                # high RTT the window stayed full for seconds, the sender never re-checked the
                # reflection, _on_req kept dropping the host's next SEND_BLOCK_REQ as 'busy', and the
                # party exchange stalled. poll_send_done acts only in HOLD (idempotent; emits nothing -
                # the held fragment is already in the reliable window). (Root-cause fix, verified against the native-Pia reference capture.)
                self.engine.poll_send_done()
            if self._dbg is not None:                 # per-VBlank block-send emission trace (debug-only)
                _snd = getattr(self.engine, "sender", None)
                self._dbg.append({"tick": tick, "inflight": _inflight_gate, "kacks": queued,
                                  "window_gated": _gated, "gba_emitted": inner is not None,
                                  "gba_len": len(inner) if inner else 0,
                                  "sender": (_snd.state, _snd.index, _snd.count) if _snd else None})
        # 4. bulk-ack LAST (reference capture order K-T-A). Pure ack (FLAGSA_CTRL): carries recv_next (the contiguous gap)
        #    + the selective mask. RATE-LIMITED to ACK_PERIOD (~8.5/s, the real client's rate) and emitted ONLY
        #    when one is owed (received host data) or we have a gap to NACK - so it PIGGYBACKS on a data datagram
        #    when we're already sending one, and goes standalone only at the floor. (Root-cause fix, measured:
        #    the old `if batch or _ack_owed or due` emitted a STANDALONE pure-ack datagram nearly every VBlank
        #    (~30/s, 95% of OUT datagrams) -> half-duplex flood -> host->us return collapsed to ~9/s -> send->ack
        #    RTT 1.8s vs the real client's 24ms on the SAME bridge -> 6-frame window pushed ~3/s -> block crawl.)
        due = (tick - self._last_ack_tick) >= ACK_PERIOD
        if due and (self._ack_owed or self.rel.recv_ooo):
            batch.append((None, reliable.FLAGSA_CTRL, self.rel.ack_payload()))
            self._ack_owed = False
            self._last_ack_tick = tick
        self._tx_reliable_batch(batch)

    def _ensure_ni(self):
        """Build the NI sender once we have an identity (after the host accepts our 'C'). The 26-byte
        NI src is the child's RfuGameData connection config, CONSTRUCTED from our sim identity (the
        engine's LinkPlayer: version, public OT id, OT name) - not hardcoded reference-capture bytes."""
        if self._ni_built:
            return
        self._ni_built = True
        lp = getattr(self.engine, "lp", None) or linkplayer.LinkPlayer()
        src = ni.build_game_data(version_low=lp.version & 0xFF,
                                 trainer_id=lp.trainer_id & 0xFFFF, ot_name=lp.name)
        self._ni = ni.NISender(src)

    def _gba_frame(self):
        """Build this VBlank's gba-app 'T' (0x54) frame, emitting ONE slot:

          1. NI handshake (after the host's 'A', BEFORE any UNI): drive the librfu NI sender one
             sub-frame per VBlank (game-data delivery) until it is exhausted.
          2. UNI trade slot: rfu.uni_slot(SlotBuilder.build(engine.tick())) wrapped in the child UNI
             LLSF - the trade engine's work, an all-zero IDLE slot, or (in the overworld/SEAT phase,
             ONLY AFTER establishment) a 0xBE00 held-keys keepalive.

        The held-keys gate is the C2 fix: held keys + sit() fire ONLY while engine.established
        (gReceivedRemoteLinkPlayers: both LinkPlayer blocks exchanged) AND engine.in_seat_phase (still
        in the overworld/cable seat, before the trade menu). Pre-establishment idle VBlanks are bare
        all-zero IDLE slots (tag untouched), so our tagged 0xBE00 never races ahead of the NI/block
        handshake and faults the host's childSendCmdId check. Held keys never override a real
        block/LINKCMD slot (we ask the engine first; held keys take an IDLE slot only).

        The ts (body[0:4]) is the per-NEW-frame u32 counter (+1 per new T; reused on retransmit, which
        re-offers the already-built bytes). Single slot per frame, one frame per VBlank (clock-slave)."""
        # NI handshake first (only while connected to the host's RFU, before steady UNI). The post-'A'
        # order is: our SEND-NI (game data) -> recv-NI (ack the host's own NI) -> UNI. We do NOT go UNI
        # until BOTH our send-NI is finished AND the host's NI is complete (received + all its sub-frames
        # acked); going UNI early races a UNI slot ahead of the host's still-open NI and faults the link.
        if self.conn is not None and self._gba_accepted and not self._ni_done:
            self._ensure_ni()
            # 1. drive our send-NI to completion first (one sub-frame per host slot / credit). Single
            #    pass - Pia Reliable guarantees delivery+order under us, so we don't stop-and-wait.
            if not self._ni.done:
                slot = self._ni.next_slot()
                if slot is not None:
                    return self._wrap_t(slot)
            # 2. our send-NI is exhausted: keep acking the host's NI until its NULL terminator. Re-emit
            #    the CURRENT recv-NI ack (mirroring the host's latest NI sub-frame, ack=1 sz=0) once per
            #    host slot through the repeated NI_END (the host needs that ack to advance to NULL). Once
            #    the host's NULL is seen, go QUIET (return None -> K/bulk-acks only) until it enters UNI:
            #    re-emitting the stale NI_END ack across the ~2.4s join-textbox gap is the malformed slot
            #    that faulted the host's RFU link ("Communication error").
            if not self._host_uni_seen:
                if self._cur_ni_ack is not None and not self._host_ni_null_seen:
                    return self._wrap_t(self._cur_ni_ack)
                return None
            # 3. the host has entered UNI (sent a state-4 slot) => its NI is complete and acked -> UNI.
            self._ni_done = True
            self.log("[sim] NI handshake complete (host entered UNI) -> entering UNI trade phase")
            self.info("Join handshake complete.")

        # engine.tick() returns the 7-int slot, OR None on a barrier frame whose want_emit() has
        # nothing to emit this VBlank (e.g. the post-trade save chain idling between echoes). None == an
        # IDLE slot here, so coerce to [0]*7 rather than crashing on words[0] (observed: post-commit crash).
        words = self.engine.tick() or [0] * 7
        if (self.linkstate is not None and (words[0] & 0xFFFF) == 0
                and getattr(self.engine, "established", False)
                and getattr(self.engine, "host_in_seat", False)
                and getattr(self.engine, "in_seat_phase", True)):
            # held-keys keepalive + sit, ONLY once the host is at its seat (host_in_seat) AND we are still
            # in the seat phase (before the party exchange latches seat_phase_over) (seat-barrier).
            words = self.linkstate.tick()
        cmd14 = self.slot.build(words)
        return self._wrap_t(rfu.uni_slot(cmd14))

    def _wrap_t(self, slot):
        """Wrap one complete slot (NI sub-frame or rfu.uni_slot(...)) in a child 'T' frame with the
        next u32 ts, advancing the counter (+1 per NEW frame)."""
        frame = gbaframe.wrap_t(slot, self.ts)
        self.ts = (self.ts + 1) & 0xFFFFFFFF
        return frame

    def _reliable_trade_payload(self):
        """Offline (conn=None) path: build ONE Reliable frame carrying this VBlank's gba 'T'. The K-ack
        layer / NI handshake are live-only (driven by the host's RFU which the offline ReplayTransport
        does not provide an 'A' for), so this stays the bare UNI/idle 'T' the offline tests expect."""
        frame = self._gba_frame()
        rel = reliable.build_reliable(self.out_seq, self.last_in_seq, frame)
        self.out_seq = (self.out_seq + 1) & 0xFFFF
        return rel

    # ---- one VBlank --------------------------------------------------------
    def tick(self):
        self._tick += 1                  # drives the ReliableLink retransmit timers
        for datagram, src_ip in self.t.recv():
            self.process_datagram(datagram, src_ip)
        # S0 handshake + RTT replies; each outbox entry is a dict carrying its own stage var-ids and
        # Pia framing (compress/footer/establishing), matched byte-for-byte to the reference capture [pia_connect].
        if self.conn:
            if hasattr(self.conn, "maybe_originate_rtt"):
                self.conn.maybe_originate_rtt(self._tick)   # liveness RTT probe (dst=0x0001)
            for e in self.conn.drain():
                self._send(e["proto"], e["payload"], dst_var=e["dst"], src_var=e["src"],
                           compress=e["compress"], footer=e["footer"],
                           establishing=e["establishing"], unicast=e.get("unicast", True),
                           pktid=e.get("pktid"), footer_var=e.get("footer_var"))
        # Reliable traffic only once the Pia connection is up. Live (conn present): drive the full
        # sliding-window connection (open stream + bulk-acks + gba frame) so the host engages its
        # own Reliable stream. Offline replay/tests (conn=None): emit the bare gba frame as before.
        if self.connected:
            if self.conn is not None:
                self._drive_reliable()
            else:
                self._send(reliable.PROTO_RELIABLE, self._reliable_trade_payload(),
                           dst_var=int.from_bytes(self.host_var, "big"),
                           src_var=int.from_bytes(self.our_var, "big"),
                           compress=False, footer=True, establishing=False)

    def close(self):
        if self._cap:
            self._cap.close()
