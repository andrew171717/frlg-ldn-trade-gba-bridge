"""RFU block transfer - the ACK-gated CHILD send sub-FSM + the receive reassembler.

Loss tolerance is first-class here (the wire is lossy and the capture is full of resends):
  * RECEIVE: fragment writes are idempotent and order-independent (a bitmask of received
    indices); duplicate/reordered/retransmitted fragments converge to the same block; an INIT
    resend of the SAME (count,owner) does NOT wipe progress.
  * SEND: every stage RESENDS until the host's wire-observable reflection (IN owner=0x81, fed
    into peer-1) acks it - INIT until echoed, then stream, then HOLD the last fragment and
    re-queue ONLY the still-missing fragments (HandleSendFailure) until receivedFlags is full.
    A resend-count watchdog advances if the reflection stalls (so it never hangs offline).

Ports Rfu_InitBlockSend / SendNextBlock / SendLastBlock / HandleSendFailure
[link_rfu_2.c:1333-1421, 1015-1042] and RfuHandleReceiveCommand [link_rfu_2.c:1125-1231].
"""

import math

from . import rfu

FRAG_BYTES = 12


def frag_count(nbytes):
    return max(1, math.ceil(nbytes / FRAG_BYTES))


def all_received_mask(count):
    return (1 << count) - 1


# ---------------------------------------------------------------------------
# Receive side
# ---------------------------------------------------------------------------
class RecvBlock:
    """Reassembly state for one peer (mpId). Idempotent + retransmit/reorder tolerant."""

    def __init__(self):
        self.count = 0
        self.owner = None
        self.flags = 0
        self.buf = bytearray()
        self.receiving = False
        self.done = False
        self.last_index = -1            # raw low byte of last SEND_BLOCK = gate (1)
        self.epochs = 0

    def on_init(self, count, owner):
        # New epoch only when size changes or we're not mid-block; a same-size INIT resend
        # mid-transfer is treated as idempotent (keeps accumulated fragments).
        if (not self.receiving) or self.done or count != self.count:
            self.count = count
            self.owner = owner
            self.flags = 0
            self.buf = bytearray(count * FRAG_BYTES)
            self.receiving = True
            self.done = False
            self.last_index = -1
            self.epochs += 1

    def on_block(self, index, frag12):
        if not self.receiving or not (0 <= index < self.count):
            return
        self.last_index = index
        self.flags |= (1 << index)
        self.buf[index * FRAG_BYTES:index * FRAG_BYTES + FRAG_BYTES] = bytes(frag12[:FRAG_BYTES])
        if self.flags == all_received_mask(self.count):
            self.done = True

    def data(self):
        return bytes(self.buf)

    def consume(self):
        """Return the completed block and arm for the next epoch (mirrors ResetBlockReceivedFlag)."""
        d = self.data()
        self.receiving = False
        self.done = False
        self.flags = 0
        return d


class BlockReceiver:
    """Dispatches the positional IN slots of a frame to per-peer reassemblers and surfaces
    completed blocks + the latest LINKCMD/REQ the host sent."""

    def __init__(self, max_peers=5):
        self.peers = [RecvBlock() for _ in range(max_peers)]
        self.last_req = None            # most recent IN SEND_BLOCK_REQ reqtype
        self.last_cmd = {}              # mpId -> last parsed slot dict

    def feed_frame(self, unwrapped):
        """unwrapped = gbaframe.parse_in(...) of an IN host frame. Returns (completed, reqs) where
        completed = [(mpId, count, data), ...] for blocks that finished on this frame, and
        reqs = [reqtype, ...] for SEND_BLOCK_REQ slots seen (host pulling a block)."""
        completed, reqs = [], []
        if not unwrapped:
            return completed, reqs
        for mpid, slot in unwrapped.get("positional", []):
            d = rfu.parse_slot(slot)
            if d is None:
                continue
            self.last_cmd[mpid] = d
            peer = self.peers[mpid] if mpid < len(self.peers) else None
            if d["op"] == rfu.SEND_BLOCK_REQ:
                self.last_req = d["reqtype"]
                reqs.append(d["reqtype"])
            elif peer is None:
                continue
            elif d["op"] == rfu.SEND_BLOCK_INIT:
                peer.on_init(d["count"], d.get("owner_raw"))
            elif d["op"] == rfu.SEND_BLOCK:
                was_done = peer.done
                peer.on_block(d["index"], d["frag"])
                if peer.done and not was_done:
                    completed.append((mpid, peer.count, peer.data()))
        return completed, reqs


# ---------------------------------------------------------------------------
# Send side (CHILD, ACK-gated) - one block at a time
# ---------------------------------------------------------------------------
INIT, STREAM, HOLD, DONE = "init", "stream", "hold", "done"


class BlockSender:
    """ACK-gated child block send. tick(ack) -> the 7-int gSendCmd for this VBlank (idle when
    waiting/done). `ack` is the peer-1 RecvBlock (the host's reflection of our block); pass None
    to run purely on the resend watchdog (offline)."""

    def __init__(self, data, owner=1, watchdog_init=4, watchdog_hold=6, trust_pia=False):
        self.data = bytes(data)
        self.count = frag_count(len(self.data))
        self.owner = owner
        self.state = INIT
        self.index = 0
        self._init_sends = 0
        self._hold_sends = 0
        self._rr = 0                    # round-robin cursor for re-queueing missing frags
        self.watchdog_init = watchdog_init
        self.watchdog_hold = watchdog_hold
        # trust_pia: send each fragment exactly ONCE (fire-and-forget) instead of the decomp's
        # re-send-until-the-host-confirms loop. The decomp loop is FAITHFUL to the Switch (its
        # HandleBlockSend/SendNextBlock/SendLastBlock/HandleSendFailure have ZERO REVISION branches -
        # a real Switch re-sends identically), but it exists for the GBA's LOSSY raw RFU adapter. Over
        # our high-RTT bridge the emulator tunnels through Pia's RELIABLE layer, so Pia already delivers
        # (+retransmits) every fragment; the emulator re-send is then pure REDUNDANCY that floods Pia
        # (verified: 335 reliable frames generated for a 17-fragment block; Pia delivered 327, the host
        # RFU faulted on the redundant torrent). On a real Switch-to-Switch LDN the host confirms in one
        # quick round-trip so the loop never accumulates; only our bridge's latency turns it into a flood.
        # Hence this is a BRIDGE adaptation, not a "more faithful" reading - default OFF, the live tool
        # turns it ON.
        self.trust_pia = trust_pia

    @property
    def done(self):
        return self.state == DONE

    def _chunk(self, index):
        return self.data[index * FRAG_BYTES:index * FRAG_BYTES + FRAG_BYTES]

    def _init_acked(self, ack):
        return ack is not None and ack.receiving and ack.count == self.count

    def tick(self, ack=None):
        if self.state == DONE:
            return [0] * 7

        if self.state == INIT:
            self._init_sends += 1
            # HandleBlockSend (CHILD) [link_rfu_2.c:1366-1382]: re-send SEND_BLOCK_INIT every frame UNTIL the
            # host echoes a SEND_BLOCK_INIT (its recvBlock is armed) -> STREAM. FAITHFUL: no give-up on the
            # live path (the host WILL echo; Pia delivers our INIT and its echo). Streaming before the host
            # armed its recvBlock drops fragments. watchdog_init is ONLY the offline (no-reflection) backstop.
            #   trust_pia: don't wait for the round-trip echo. Pia delivers our INIT RELIABLY and IN-ORDER
            #   (the host always processes it before the fragments that follow), so a watchdog_init-frame
            #   bound is enough to arm the host; waiting for the echo just costs a round-trip per block.
            if self.trust_pia:
                armed = self._init_acked(ack) or self._init_sends > self.watchdog_init
            else:
                armed = self._init_acked(ack) or (ack is None and self._init_sends > self.watchdog_init)
            if armed:
                self.state = STREAM
                self.index = 0
            else:
                return rfu.init_words(self.count, self.owner)
            # fall through to stream this same tick once INIT is acked

        if self.state == STREAM:
            idx = self.index
            words = rfu.send_block_words(idx, self._chunk(idx))
            if idx >= self.count - 1:
                # trust_pia: FIRE-AND-FORGET. Pia has each fragment queued + will deliver/retransmit it, and
                # the trade FSM advances on RECEIVING the host's block (GetBlockReceivedStatus()==3
                # [trade.c:1454-1546]), NOT on our send completing - so we DONE here, skipping the redundant
                # HOLD re-send that floods the bridge. Faithful: HOLD the last fragment + re-send the missing.
                self.state = DONE if self.trust_pia else HOLD
                self._hold_sends = 0
            else:
                self.index += 1
            return words

        if self.state == HOLD:
            self._hold_sends += 1
            last = self.count - 1
            full = all_received_mask(self.count)
            # SendLastBlock (CHILD) [link_rfu_2.c:1398-1416], FAITHFUL: re-send the LAST fragment every frame;
            # when the host acks the last index (ack.last_index == count-1, = gRecvCmds[mpId][0]==count-1):
            #   - it has ALL (receivedFlags == sAllBlocksReceived) -> DONE.
            #   - else HandleSendFailure -> re-send the still-missing fragments until it does.
            # CONFIRM-DRIVEN, no DONE-and-proceed watchdog on the live path: we KEEP sending until the host
            # confirms (Pia delivers our fragments + the host's ack, so it WILL confirm). The old unconditional
            # watchdog DONE'd after 6 and left the host one fragment short -> it never requested mail = the 3/3
            # DEADLOCK; the even-older missing-round-robin re-streamed forever -> flood. The real game confirms
            # or the link's own 10s timeout errors. watchdog_hold is ONLY the offline (no-reflection) backstop.
            if ack is not None:
                if ack.last_index == last:
                    if ack.flags == full:
                        self.state = DONE
                        return [0] * 7
                    missing = self._missing(ack)
                    if missing:
                        self._rr = (self._rr + 1) % len(missing)
                        idx = missing[self._rr]
                        return rfu.send_block_words(idx, self._chunk(idx))
            elif self._hold_sends > self.watchdog_hold:
                self.state = DONE          # offline (no host reflection) backstop only
                return [0] * 7
            return rfu.send_block_words(last, self._chunk(last))

        return [0] * 7

    def _missing(self, ack):
        if ack is None or ack.count != self.count:
            return []
        return [i for i in range(self.count) if not (ack.flags >> i) & 1]
