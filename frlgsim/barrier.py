"""Standby / close-link barrier - the CHILD-INITIATED READY_EXIT_STANDBY(0x6600) /
READY_CLOSE_LINK(0x5F00) mirror [src/link_rfu_2.c:1471-1602].

WHY THIS EXISTS
  The real FRLG child reaches the SAME trade.c / trade_scene.c state the host does and calls
  SetLinkStandbyCallback() ITSELF [link.c:1353, gWirelessCommType==1 -> Rfu_SetLinkStandbyCallback
  link_rfu_2.c:1595]. The child branch of Rfu_LinkStandby [link_rfu_2.c:1566-1573] then IMMEDIATELY
  emits ONE 0x6600 (word1 = resendExitStandbyCount [link_rfu_2.c:1307-1310]) and installs
  SendReadyExitStandbyUntilAllReady. The LEADER/host branch [1577-1591] WAITS for the child's
  readyExitStandby[i] first - so a strict-ROM 2-player host (the real Switch, and our faithful
  SaveChainHost) NEVER broadcasts 0x6600 until it has RECEIVED the child's. A purely REACTIVE sim
  (one that only answers AFTER seeing the host's 0x6600) therefore DEADLOCKS at every standby barrier:
  trade-menu entry [trade.c:914-915], the menu<->scene seam [trade.c:2159-2166], cancel [trade.c:2126],
  and the 4-5 post-trade save barriers [trade_scene.c:2576,2662,2678,2702,2722-2725]. We must INITIATE.

WHAT THE REAL CHILD DOES (the behavior we imitate, GetMultiplayerId()!=0 child branch)
  * Rfu_LinkStandby [link_rfu_2.c:1566-1573]: when recvQueue empty & send slot free -> emit ONE
    0x6600 (word1 = resendExitStandbyCount [link_rfu_2.c:1307-1310]), install
    SendReadyExitStandbyUntilAllReady.
  * SendReadyExitStandbyUntilAllReady [link_rfu_2.c:1527-1548]: every frame, ++resendExitStandbyTimer;
    if recvQueue empty AND timer>60, re-emit 0x6600 + reset timer. The barrier COMPLETES when
    readyExitStandby[all] is set, which for the child means it RECEIVED the host's matching-count
    0x6600 (the recv gate [link_rfu_2.c:1178-1180] sets readyExitStandby[i]=TRUE iff
    resendExitStandbyCount == gRecvCmds[i][1]). On completion it clears readyExitStandby[], does
    resendExitStandbyCount++ (the round advances) and clears the callback (the FSM proceeds).
  * Close path [link_rfu_2.c:1497-1520]: SendReadyCloseLink emits ONE 0x5F00, then
    WaitAllReadyToCloseLink waits readyCloseLink[all]; the host's recv side sets readyCloseLink[i]
    unconditionally [link_rfu_2.c:1175-1176], so close accepts ANY count and there is no per-round
    increment (close reuses resendExitStandbyCount as a static tag [link_rfu_2.c:1308-1309]).

TWO ENTRY PATHS (both modelled)
  * INITIATE (FSM-driven, the ROM's real path): the engine reaches a standby point and calls
    initiate(). We emit our OWN-count 0x6600 every VBlank and COMPLETE when the host echoes a
    matching-count 0x6600 (then local_count++). This is what unblocks the strict-ROM host.
  * REACTIVE (robustness): if the host's 0x6600 arrives while we are IDLE (the host initiated first,
    or our INITIATE has not been called yet this VBlank), we still latch + answer it. Harmless: the
    host dedups by count via its recv gate, and a reactive answer never advances local_count past the
    host (we only ++ on a confirmed matching round).

OFFLINE WATCHDOG (why a barrier cannot hang the sim against a NON-participating mock host)
  A strict-ROM host always answers, but the broad happy-path MockHost does not run the standby
  callbacks at all (it jumps straight from the exchange to SET_MONS). The ROM relies on the host
  always being present; offline we cannot. So an INITIATED barrier that goes INITIATE_TIMEOUT frames
  without ANY host 0x6600 auto-completes (the FSM proceeds) - the same resend-watchdog philosophy as
  block.py (watchdog_init / watchdog_hold). When the host DOES participate (the faithful SaveChainHost,
  the real Switch) the matching-count echo completes the barrier first and the watchdog never fires.

RIGHT SEAT: the responder only ever uses the child branch
  (GetMultiplayerId()!=0) of link_rfu_2.c - it emits as mpId 1 with word1 = our OWN resendExit-
  StandbyCount, and reads the host's barrier from the host (mpId-0) IN slot. It never uses the
  host/left-seat leader emission logic.
"""

from . import rfu

# BarrierResponder modes.
IDLE = "IDLE"
STANDBY = "STANDBY"      # answering / initiating READY_EXIT_STANDBY (0x6600)
CLOSE = "CLOSE"          # answering / initiating READY_CLOSE_LINK (0x5F00)

# Frames an INITIATED barrier waits for ANY host 0x6600 before auto-completing so the sim never hangs
# against a host that does not run the standby callbacks (the happy-path MockHost). A strict-ROM host
# answers within a frame or two, so this only ever fires offline. Comfortably past the ROM's >60-frame
# child re-emit cadence [link_rfu_2.c:1529] so a slow/jittery participating host still completes via
# the matching-count echo, not the watchdog.
INITIATE_TIMEOUT = 120

# Frames without an observed host barrier op before a REACTIVE (host-initiated) STANDBY drops back to
# IDLE (trade resumes). Mirrors the >60 child re-emit cadence with margin. CLOSE is terminal and never
# auto-clears (we keep answering until the link drops).
IDLE_TIMEOUT = 90


class BarrierResponder:
    """CHILD-INITIATED + reactive mirror of the host's standby/close barriers. Lives between
    block.BlockReceiver and trade.TradeEngine.tick(): fed the host's mpId-0 barrier slot on every IN
    frame, and INITIATEd by the engine at each FSM standby point. While a barrier is active the engine
    goes quiescent and emits ONLY our 0x6600/0x5F00 (no block send / LINKCMD push) - a barrier and a
    block never coexist on the wire (the host only standbys when the send/recv queues are drained
    [link_rfu_2.c:1553/1569/1586])."""

    def __init__(self, log=lambda *a: None):
        self.mode = IDLE
        self.initiated = False       # this barrier was started by our FSM (vs. reactively by the host)
        self.host_count = None       # latched from the host's last IN 0x6600/0x5F00 word1 (or None)
        self.local_count = 0         # our resendExitStandbyCount mirror (climbs +1 per completed round)
        self._since_host = 0         # frames since we last saw the host's barrier op
        self._since_initiate = 0     # frames since we INITIATEd, with no host 0x6600 yet
        self.rounds = 0              # standby rounds completed (for logging/tests)
        # LIVE-only bounded burst per count (fixes a standby-flood deadlock). None = unbounded
        # (every-VBlank, the offline tests' MockHost timing depends on it + has no retransmit). When the
        # live sim sets this (BARRIER_EMITS), we emit at most this many NEW frames per count then go
        # quiet: the reference capture sends each standby ~3-4x and STOPS; emitting forever keeps the host in the same
        # round (it sees continuous count=N) -> mutual deadlock + buffer flood -> 2318-0013. Reliable
        # retransmit (live) redelivers the burst, and the host completes on the first matching reply.
        self.max_emits = None
        self._burst_for = None       # count the current burst is for
        self._burst_n = 0            # NEW frames emitted in the current burst
        self.log = log

    @property
    def active(self):
        """True while a barrier is in progress (the engine must stay quiescent)."""
        return self.mode != IDLE

    def reset_to_idle(self):
        """Drop any in-progress standby/close to IDLE (mode + initiated only; local_count preserved).
        Used when a phase boundary makes a prior reactive round stale - e.g. the seat begins and the
        warp-quiesce standbys are behind us, so the leftover reactive 0x6600 must not leak into the seat
        phase (fixes a live issue). CLOSE is terminal and is NOT reset (the teardown owns it)."""
        if self.mode == STANDBY:
            self.mode = IDLE
            self.initiated = False
            self._since_initiate = 0
            self._burst_for = None

    # ---- initiate (called by the engine when its FSM reaches a standby point) ----
    def initiate(self, kind=STANDBY):
        """Begin a CHILD-INITIATED barrier (the ROM's SetLinkStandbyCallback path). Idempotent while
        the same kind is already active. Emits our OWN-count 0x6600 (or 0x5F00) every VBlank from now
        until the host echoes a matching-count reply (or, offline, the watchdog releases us)."""
        if kind == CLOSE:
            if self.mode != CLOSE:
                self.mode = CLOSE
                self.initiated = True
                self._since_host = 0
                self._since_initiate = 0
                self.log(f"barrier: INITIATE close-link 0x5F00 (count={self.local_count})")
            return
        if self.mode == STANDBY:
            return                   # already standing by; keep emitting until it completes
        self.mode = STANDBY
        self.initiated = True
        self.host_count = None
        self._since_host = 0
        self._since_initiate = 0
        self._burst_for = None       # fresh bounded burst for this initiated round (live)
        self.log(f"barrier: INITIATE standby 0x6600 (local_count={self.local_count})")

    # ---- receive ------------------------------------------------------------
    def on_in_slot(self, parsed):
        """Called for the host's mpId==0 barrier slot every IN frame (parsed = rfu.parse_slot dict).
        Drives both completion of an INITIATEd barrier (the host echoed our count) and the reactive
        path (the host initiated and we must answer). Returns True if this slot COMPLETED the current
        standby round (the engine should then proceed past the barrier)."""
        if parsed is None:
            return False
        op = parsed.get("op")
        if op == rfu.READY_EXIT_STANDBY:
            return self._on_host_standby(parsed.get("count", 0))
        if op == rfu.READY_CLOSE_LINK:
            self._on_host_close(parsed.get("count", 0))
        return False

    def _on_host_standby(self, count):
        """Process the host's 0x6600 broadcast. The two entry paths need different completion rules:

        * CHILD-INITIATED (self.initiated, e.g. the save chain / a real-host barrier we started): the
          host ECHOING our count means readyExitStandby[us] would latch and the round PASSES
          (link_rfu_2.c:1178-1180 + 1541-1547). Complete it: local_count++ and drop to IDLE so the FSM
          proceeds. Returns True.
        * REACTIVE / host-initiated (the host broadcast first, e.g. the entry standby windows P0/P3):
          the host is parked broadcasting count C and WAITS for repeated matching-count replies. We
          MIRROR its count (so the recv gate accepts every reply) and keep answering; we only advance
          local_count when the host ADVANCES its broadcast count (the previous round passed) and we drop
          to IDLE when it stops (observe_frame's IDLE_TIMEOUT). We must NOT complete on the first match
          here or we would stop replying while the host is still waiting -> deadlock."""
        self._since_host = 0
        prev_host = self.host_count
        self.host_count = count
        if self.initiated and self.mode == STANDBY:
            # the host echoed the barrier WE initiated at our count -> the round passes.
            if count == self.local_count:
                self.local_count += 1
                self.rounds += 1
                self.mode = IDLE
                self.initiated = False
                self._since_initiate = 0
                self.log(f"barrier: child-initiated standby round complete (host echoed "
                         f"count={count}) -> local_count={self.local_count}, rounds={self.rounds}")
                return True
            return False
        # The leader RE-BROADCASTS count=N for several frames AFTER we already completed round N
        # (SendReadyExitStandbyUntilAllReady keeps sending until it confirms our ack). Once we've
        # passed N (local_count > N), that re-broadcast is NOT a new reactive round - IGNORE it.
        # (Save-stuck root cause: a child-initiated save round completed (local_count=N+1), then
        # the host's count=N re-broadcasts hit the reactive branch below, REGRESSED local_count back to
        # N, and span a spurious round - which our own re-emitted count=N (reflected by the host as a
        # 'host barrier') kept alive for ~11-25s -> the save chain crawled ~3x slow and never reached
        # the final save barriers. host_count is already updated above, so the warps' host_count gate
        # is unaffected; genuine reactive barriers (count >= local_count) still fall through.)
        if count < self.local_count:
            return False
        # REACTIVE: the host initiated. Mirror its count and keep replying.
        if self.mode != STANDBY:
            self.mode = STANDBY
            self.initiated = False
            self.log(f"barrier: host 0x6600 count={count} -> STANDBY (reactive mirror)")
        elif prev_host is not None and count != prev_host:
            # the host advanced its broadcast count: the previous reactive round passed.
            self.rounds += 1
            self.log(f"barrier: host advanced reactive round {prev_host}->{count}")
        self.local_count = count          # mirror so our reply matches the host's recv gate exactly
        self._since_initiate = 0
        return False

    def _on_host_close(self, count):
        self._since_host = 0
        self.host_count = count
        # Close is symmetric and its recv gate accepts ANY count [link_rfu_2.c:1175-1176], but we still
        # mirror the host's count into our reply so want_emit() echoes exactly what the host broadcast
        # (cosmetically faithful, and harmless to the gate).
        self.local_count = count
        if self.mode != CLOSE:
            self.mode = CLOSE
            self.initiated = False
            self.log(f"barrier: host 0x5F00 count={count} -> CLOSE (mirror reply)")

    def observe_frame(self, saw_barrier):
        """Advance the per-frame watchdogs once per IN frame. saw_barrier = did this frame carry a host
        barrier op (0x6600/0x5F00) for mpId 0?

        * An INITIATED standby with NO host barrier op for INITIATE_TIMEOUT frames auto-completes (the
          host does not participate - happy-path MockHost; we proceed so the sim never hangs).
        * A REACTIVE (host-initiated) standby that goes IDLE_TIMEOUT frames without a host barrier op
          drops back to IDLE (the host's round is over, trade traffic resumes).
        * CLOSE is terminal: it never times out (we keep answering until the host disconnects)."""
        if self.mode != STANDBY:
            return
        if saw_barrier:
            self._since_host = 0
            self._since_initiate = 0
            return
        self._since_host += 1
        if self.initiated:
            self._since_initiate += 1
            if self._since_initiate > INITIATE_TIMEOUT:
                # The host never answered our initiated barrier (offline, non-participating host).
                # Release the FSM so the sim does not hang. CRUCIALLY we do NOT increment local_count
                # here: in the ROM resendExitStandbyCount++ happens only on a REAL completion
                # (readyExitStandby[all], link_rfu_2.c:1545) - a host echo. A watchdog release is a
                # sim-only escape for a non-participating host and corresponds to NO real round, so
                # local_count must stay put. This keeps our count in lockstep with a host that DID
                # participate: barriers it skipped (watchdog-released) leave local_count unchanged, so
                # the next barrier the host DOES join still matches counts exactly [recv gate
                # 1178-1180]. (The real Switch participates in every barrier, so the watchdog never
                # fires and local_count climbs only via _on_host_standby.)
                self.mode = IDLE
                self.initiated = False
                self.log(f"barrier: INITIATE standby unanswered for >{INITIATE_TIMEOUT}f -> IDLE "
                         f"(watchdog release, local_count held at {self.local_count})")
        else:
            if self._since_host > IDLE_TIMEOUT:
                # A REACTIVE standby (the host broadcast first, we mirrored its count) that the host
                # has now stopped broadcasting: the FINAL round it was on has passed (the host cleared
                # its callback and did resendExitStandbyCount++ [link_rfu_2.c:1545]). Mirror that final
                # ++ so local_count = lastHostCount + 1 stays in lockstep, then release to IDLE so trade
                # traffic resumes. (Distinct from the INITIATE watchdog above, where the host NEVER
                # answered and NO round passed - that release must not increment.)
                self.local_count += 1
                self.rounds += 1
                self.mode = IDLE
                self.log(f"barrier: host stopped 0x6600 for >{IDLE_TIMEOUT}f -> IDLE "
                         f"(final reactive round passed, local_count={self.local_count})")

    # ---- emit (consulted by tick() only when the engine is otherwise idle) ---
    def want_emit(self):
        """Return the 7-int pre-tag gSendCmd run for this VBlank, or None if no barrier is active.
        We emit our OWN resendExitStandbyCount (link_rfu_2.c:1307-1310): the child broadcasts its own
        count, and the host accepts it iff it matches the host's current round. We emit every VBlank we
        are in a barrier (a superset of the ROM's >60-frame cadence). LIVE: bounded to max_emits NEW
        frames per count (then quiet, retransmit delivers + host completes) so we don't keep the host in
        the round forever -> deadlock/flood. OFFLINE (max_emits None): every VBlank, as the tests expect."""
        if self.mode not in (STANDBY, CLOSE):
            return None
        if self.max_emits is not None:
            if self._burst_for != self.local_count:      # new round/count -> fresh bounded burst
                self._burst_for = self.local_count
                self._burst_n = 0
            if self._burst_n >= self.max_emits:
                return None                              # burst delivered/in-flight; quiet until round advances
            self._burst_n += 1
        if self.mode == STANDBY:
            return rfu.exit_standby_words(self.local_count)
        return rfu.close_link_words(self.local_count)
