"""Pia MESSAGE tiling + Reliable(10) sub-header (the inverse of the wire parser).

A decrypted+decompressed Pia application blob =
    <message>* <2-byte sender station-id footer> <optional 0xff padding>
Each message has a presence-flag header (fields inherit from the previous message when their
bit is clear) then `size` payload bytes. The trade rides proto=Reliable(10); its 8-byte
sub-header carries the wrap-aware BE seq/ack and then the gba-app frame (flagsA=0x07).
"""

from dataclasses import dataclass, field

PROTO_NAMES = {1: "Net", 3: "RTT", 4: "Sync", 5: "Unreliable",
               9: "Clock", 10: "Reliable", 13: "Session"}
PROTO_RELIABLE = 10

# Station-id footer tokens (BE u16). The reference capture: HOST var=0x7620, JOINER var=0xc493 (were SWAPPED).
# The footer is the RECIPIENT var, so an OUT guest->host blob's footer = STATION_HOST (0x7620).
STATION_HOST = 0x7620
STATION_JOINER = 0xc493

# Reliable sliding-window flags [wiki Reliable-Sliding-Window]: 1=AppData 2=MsgStart 4=MsgEnd
# 8=Initialized 16=zlib 32=Reset 64=ResetAck. A single-fragment app message = Start|End|AppData.
FLAGSA_GBA = 0x07       # AppData|Start|End - a complete single-fragment gba-app data frame
FLAGSA_INIT = 0x0f      # FLAGSA_GBA|Initialized - the STREAM-OPENING frame (host ignores data until
                        # it sees this; we never sent it -> the host stayed silent on RTT only)
FLAGSA_CTRL = 0x00      # no AppData -> the payload is bulk-acknowledgement data

# Fast-retransmit cap (ticks) for the GAP (oldest unacked / peer-NACKed hole). We re-send it at
# min(SRTT, this), so a bufferbloat-inflated SRTT (~1s) can't stall gap recovery. 8 ticks ~= 130ms = the
# ORACLE target: native Pia (the native-Pia reference capture, same bridge) re-sends a lost frame in ~130ms median. ONE frame, not the
# window. [Was 1020ms for us -> window jammed; native's flows because it recovers this fast.]
FAST_RTX_CAP = 8

# The reference capture #15: the gba-app's FIRST Reliable payload is a title/version metadata frame, carried on the
# stream-opening (INIT) frame. Replicated verbatim (LeafGreen, English) - a FireRed host accepts it.
METADATA_FRAME = bytes.fromhex("4a002a005801004c656166477265656e5f65" + "00" * 28)


def build_bulk_ack(next_expected, mask=b"\x00" * 16, stream_id=0):
    """Bulk-acknowledgement payload for a FLAGSA_CTRL frame [wiki 'Ack Data']: stream id, entry
    count, then per entry an ack id (every seq below it is acked) + a 128-bit gap mask. The reference capture sends
    one entry, no gaps: `00 01 <next_expected:2 BE> <16 zero>` (e.g. acking host fff0 -> 0001fff1)."""
    return bytes([stream_id & 0xFF, 1]) + (next_expected & 0xFFFF).to_bytes(2, "big") + mask


def parse_bulk_ack(payload):
    """-> (ack_id, mask) from a FLAGSA_CTRL payload. ack_id = next-expected seq (every seq below it
    is acked); mask = 128-bit gap bitmap (`ack_id + 1 + index` is acked when bit `index` is set).
    Returns (None, b'') if too short."""
    if len(payload) < 4:
        return None, b""
    return int.from_bytes(payload[2:4], "big"), payload[4:20].ljust(16, b"\x00")


def _seq_lt(a, b):
    """a < b in 16-bit wrap-around sequence space (RFC1982-style)."""
    d = (b - a) & 0xFFFF
    return d != 0 and d < 0x8000


class ReliableLink:
    """A Pia reliable sliding window (one per peer) with RETRANSMISSION - frames WILL drop on this
    radio, and an un-retransmitted reliable stream deadlocks the instant one does (the peer stalls on
    the gap, our INIT/block frames never land). Handles both directions:

      * SEND: hands out sequence ids, BUFFERS every unacked data frame, and re-offers any frame that
        hasn't been acked within `rtx_ticks` VBlanks until the peer's bulk-ack frees it.
      * RECV: delivers data frames to the app IN ORDER, BUFFERS out-of-order frames across a gap, and
        DEDUPES retransmits, so a dropped/duplicated frame never corrupts the gba-app stream.

    Control/ack frames are NOT tracked here (they carry no sequence id - the sim sends them at the
    window's base seq). `window_lo` is the reliable header's "lowest pending ack" field."""

    def __init__(self, start=0xFFF0, rtx_ticks=4, max_inflight=128, rto_floor=4, rto_ceil=128,
                 sack_free=False):
        # sack_free: free the send window on the peer's selective-ack MASK (selective-repeat sender), not just
        # the cumulative ack. OFF by default (cumulative-only = safe). It broke the live LinkPlayer once, so it
        # is gated behind this flag and validated via the offline harness before re-enabling.
        self.sack_free = sack_free
        self.out_seq = start              # next send sequence id to hand out
        self.window_lo = start            # lowest unacked seq (header "lowest pending ack")
        self.unacked = {}                 # seq -> [flagsA, inner, last_tx_tick, resends]
        self.recv_next = start            # next in-order seq we expect from the peer (contiguous high-water)
        self.recv_buf = {}               # seq -> payload (on_data in-order path, offline/tests)
        self.recv_ooo = set()            # out-of-order received seqs > recv_next (live path, for the selective
                                         # ack mask) - populated by note_received(); empty on the on_data path
        self.rtx_ticks = rtx_ticks        # fallback RTO (ticks) until we have an SRTT sample
        self.max_inflight = max_inflight
        # ADAPTIVE RTO: the retransmit timer MUST exceed the link RTT or every unacked frame
        # is re-sent before its ack can return (flood). The reference capture's flat 121ms timer is an artifact of its fast
        # (~20ms) link; our bridge is ~440ms median, spiking to ~2s. So we measure SRTT from clean acks and
        # set RTO = clamp(1.5*srtt, floor, ceil) with mild per-resend backoff (x1.25, matching the reference capture's
        # measured g2/g1~=1.23, NOT x2).
        self.srtt = None                  # smoothed RTT in ticks (None until the first clean sample)
        self.rttvar = 0.0
        self.rto_floor = rto_floor
        self.rto_ceil = rto_ceil
        # FAST-RETRANSMIT (measured): the peer NACKs the exact missing frame via the selective-ack
        # MASK in its bulk-ack (non-zero on the lossy live link - the reference capture's clean dump always had it zero, the
        # premise of the now-revised "ignore the mask" rule). When the mask is set, ack_id is a CONFIRMED
        # hole (the peer has frames buffered beyond it), so we re-send ack_id at ~SRTT cadence instead of
        # letting the RTO back off to seconds. _peer_gap = that seq (or None when the ack carries no mask).
        self._peer_gap = None

    # -- send side --------------------------------------------------------
    def inflight(self):
        return len(self.unacked)

    def send_low(self):
        """The header 'lowest sequence id pending ack' field: our OWN lowest unacked send
        seq (the sender window base), NOT the cached peer ack. = the oldest unacked seq in wrap order, or
        out_seq when nothing is outstanding."""
        if not self.unacked:
            return self.out_seq
        return min(self.unacked, key=lambda s: (s - self.window_lo) & 0xFFFF)

    def queue(self, inner, flagsA, tick):
        """Assign a sequence id to a new DATA frame and buffer it for retransmission."""
        seq = self.out_seq
        self.out_seq = (self.out_seq + 1) & 0xFFFF
        self.unacked[seq] = [flagsA, inner, tick, 0, tick]  # [flagsA, inner, last_tx, resends, first_tx]
        return seq

    def _sample_rtt(self, r):
        if r <= 0:
            return
        if self.srtt is None:
            self.srtt, self.rttvar = float(r), r / 2.0
        else:
            self.rttvar = 0.75 * self.rttvar + 0.25 * abs(self.srtt - r)
            self.srtt = 0.875 * self.srtt + 0.125 * r

    def rto(self):
        """Current retransmit timeout in ticks, tracked DYNAMICALLY from the link via Jacobson's estimator
        RTO = SRTT + 4*RTTVAR (the standard TCP formula). This adapts to both the mean RTT and its VARIANCE
        (jitter) on its own - a stable fast link gives RTO~SRTT (small), a jittery/slow link widens it
        automatically - so we never hand-tune a per-link timer. floor/ceil are just wide safety rails (a
        minimum frame-time and a sanity cap), NOT the operating point. rtx_ticks is the fallback until the
        first clean RTT sample seeds SRTT."""
        if self.srtt is None:
            return self.rtx_ticks
        # Pia's reliable layer uses RTO = 33ms + 1.4*RTT, no backoff. 33ms = rto_floor (2 ticks);
        # 1.4*srtt is the RTT term. (rto_ceil kept only as a sanity rail; the host has no clamp but a lean
        # window keeps srtt at the physical RTT so it never approaches the rail.)
        return max(self.rto_floor, min(self.rto_ceil, int(self.rto_floor + 1.4 * self.srtt + 0.5)))

    def on_ack(self, ack_id, mask=None, tick=None):
        """SELECTIVE-REPEAT sender: free EVERY frame the peer says it has - the cumulative run below ack_id
        AND the out-of-order frames the MASK marks received. [MECHANISM FIX, wiki Reliable-Sliding-Window /
        Ack Data: 'the acknowledgement mask allows up to 128 sequence ids behind a gap to be acknowledged. If
        ack_mask & (1<<index) is set, then ack_id+1+index is marked as received.']

        We previously freed ONLY on the cumulative ack_id and threw the mask away - i.e. a Go-Back-N SENDER
        against a selective-repeat RECEIVER. When ONE frame dropped, the host buffered everything behind the
        gap and acked it via the mask, but WE kept it all 'unacked' -> our send window FROZE behind the gap
        (full of frames the host already had) and the cumulative ack only crept forward 1-2 per host ack as we
        recovered the hole -> ~17/s crawl + window-bound 118ms stalls. Native Pia (the native-Pia reference capture) frees on the mask,
        so its window never freezes and it flows at the host's ack rate. Freeing on the mask is SAFE here (the
        wiki defines the exact bit->seq mapping; we act only on bits the host set = frames it confirmed). What
        remains 'unacked' after this is EXACTLY the real holes (ack_id and any cleared mask bits); those are
        what due_retransmits re-sends. tick drives SRTT (clean sample only for never-retransmitted frames)."""
        if ack_id is None:
            return
        for seq in list(self.unacked):
            if _seq_lt(seq, ack_id):                       # cumulative run
                entry = self.unacked.pop(seq)
                if tick is not None:
                    if entry[3] == 0:                      # never retransmitted -> unambiguous (Karn) sample
                        self._sample_rtt(tick - entry[2])
                    elif self.srtt is None:
                        # BOOTSTRAP: srtt is still unseeded and only RETRANSMITTED frames are being acked.
                        # On a high-RTT bridge the first frames retransmit before their ack (RTO == the tiny
                        # rtx_ticks fallback), so Karn never gets a clean sample -> srtt stays None -> RTO
                        # stuck at rtx_ticks -> EVERYTHING retransmits prematurely (~53% vs the native-Pia reference capture's 12%) ->
                        # bufferbloat that crawls the sequential post-trade save barriers. Seed srtt from the
                        # FIRST send (entry[4]): if the ack is for a later resend this OVERESTIMATES the RTT,
                        # which is SAFE (RTO too high -> no premature resend -> subsequent frames get CLEAN
                        # acks that refine srtt down to the true RTT). Breaks the bootstrap deadlock so the
                        # adaptive RTO actually engages. (fixes the live save-crawl; the native-Pia reference capture keeps a 12% rtx rate)
                        self._sample_rtt(tick - entry[4])
        self.window_lo = ack_id
        # SELECTIVE free (gated by sack_free; default OFF) - free the out-of-order frames the MASK marks
        # received [wiki: bit i set => ack_id+1+i received; mask = little-endian 128-bit]. This unfreezes the
        # send window behind a gap (selective-repeat sender). Verified LE byte order vs the native-Pia reference capture. It re-broke the
        # live LinkPlayer once (amplified block re-streaming), so it's OFF until the offline harness confirms
        # it's correct (no dropped frame) + faster. [REVERTED for live; flag lets the harness exercise it.]
        if self.sack_free and mask is not None:
            maskint = int.from_bytes(mask, "little")
            i = 0
            while maskint:
                if maskint & 1:
                    self.unacked.pop((ack_id + 1 + i) & 0xFFFF, None)
                maskint >>= 1
                i += 1
        # CONFIRMED hole: the peer cumulatively wants ack_id but its mask shows frames buffered past it ->
        # ack_id was dropped. (ack_id stays unacked - never freed above.) Drives the fast-retransmit tier.
        if mask is not None and any(mask) and ack_id in self.unacked:
            self._peer_gap = ack_id
        else:
            self._peer_gap = None

    def due_retransmits(self, tick, limit=None):
        """[(seq, flagsA, inner)] for unacked frames due for resend (oldest first). Stamps them re-sent.

        Pia uses GAP-ONLY selective repeat with two triggers and NO exponential backoff:
          - TIMEOUT: resend a frame when now - last_tx >= RTO (RTO = 33ms + 1.4*RTT, self.rto()); the host
            re-arms the same deadline on each resend (no backoff).
          - FAST-RETRANSMIT: a frame the peer NACKed via its selective mask (_peer_gap) resends ~immediately
            (at the floor) - the host fast-retransmits on a SINGLE selective-NACK.
        limit=None (offline/tests) returns ALL due (gap order); limit=N (LIVE) is gap-targeted (the oldest <=N,
        STOP at the first not-yet-due) - we keep in-flight <= the host's tiny receive credit so this is at most
        a couple frames anyway."""
        base_rto = self.rto()
        out = []
        for seq in sorted(self.unacked, key=lambda s: (s - self.window_lo) & 0xFFFF):
            entry = self.unacked[seq]
            # NACK'd (mask-confirmed hole) -> fast-retransmit at the floor; else the plain RTO timeout. No backoff.
            eff_rto = self.rto_floor if seq == self._peer_gap else base_rto
            if tick - entry[2] >= eff_rto:
                entry[2] = tick
                entry[3] += 1
                out.append((seq, entry[0], entry[1]))
                if limit is not None and len(out) >= limit:
                    break
            elif limit is not None:
                break          # gap-targeted: don't skip past a not-yet-due frame to re-send buffered ones
        return out

    # -- receive side -----------------------------------------------------
    def on_data(self, seq, payload):
        """Accept a received DATA frame; return the list of payloads now deliverable IN ORDER
        (empty for a future/duplicate frame)."""
        if seq == self.recv_next:
            out = [payload]
            self.recv_next = (self.recv_next + 1) & 0xFFFF
            while self.recv_next in self.recv_buf:
                out.append(self.recv_buf.pop(self.recv_next))
                self.recv_next = (self.recv_next + 1) & 0xFFFF
            return out
        if _seq_lt(self.recv_next, seq):              # ahead of the gap -> buffer it
            self.recv_buf[seq] = payload
        return []                                     # duplicate/old, or buffered

    def note_received(self, seq):
        """SELECTIVE-REPEAT receiver accounting for the live path: record a received DATA seq WITHOUT in-order
        delivery (the gba-app processes frames as they arrive, order-tolerant). Advances recv_next over the
        contiguous run and keeps out-of-order seqs in recv_ooo for the selective ack mask. Idempotent.

        [Replaces the old 'ack to the HIGHEST received seq' hack, which LIED about gaps (claimed frames we
        hadn't got) so the host never retransmitted them - we leaned on the gba-app re-pull, which was SLOW.
        Now we ack the true contiguous high-water + a selective mask, so the host FAST-RETRANSMITS its drops
        (Pia's ReliableSlidingWindow resends on a single selective-NACK). The mask is what makes
        an honest ack safe - no stall, because the gap recovers in ~1 RTT instead of waiting the host RTO.]"""
        if seq == self.recv_next:
            self.recv_next = (self.recv_next + 1) & 0xFFFF
            while self.recv_next in self.recv_ooo:
                self.recv_ooo.discard(self.recv_next)
                self.recv_next = (self.recv_next + 1) & 0xFFFF
        elif _seq_lt(self.recv_next, seq):
            self.recv_ooo.add(seq)
        # else: seq < recv_next (already counted) or duplicate -> ignore

    def ack_payload(self):
        """Bulk-ack: CUMULATIVE next-expected (recv_next) + a SELECTIVE MASK of the out-of-order frames we
        hold (recv_ooo), so the peer FAST-RETRANSMITS exactly its dropped frames (the host's
        ReliableSlidingWindow resends on a single selective-NACK; mask bit i set => recv_next+1+i
        received, LSB-first within each byte). recv_ooo is populated by note_received (live path); on the
        offline on_data path it stays empty -> zero mask (unchanged, the safe cumulative-only behavior).
        NOTE the earlier 'a selective mask broke the host's retransmit' was a FORMAT bug (we built the mask
        wrong); the RE pins the exact LSB-first ack_id+1+i layout, which is what we emit here."""
        mask = bytearray(16)
        for s in self.recv_ooo:
            i = (s - self.recv_next - 1) & 0xFFFF
            if i < 128:
                mask[i >> 3] |= (1 << (i & 7))
        return build_bulk_ack(self.recv_next, bytes(mask))


@dataclass
class Message:
    flags: int
    proto: int
    size: int
    payload: bytes
    msgflags: int = 0
    hdr_bytes: bytes = b""          # exact header slice (for byte-identical reserialization)

    def serialize(self):
        return self.hdr_bytes + self.payload


def parse_messages(data):
    """Tile a Pia application blob into messages. Returns (list[Message], consumed)."""
    msgs = []
    i, n = 0, len(data)
    mf, size, proto = 0, None, None
    while i < n:
        fl = data[i]
        if fl == 0xff or (fl & 0xF0):
            break
        if fl == 0 and size is None:
            break
        hdr_start = i
        j = i + 1
        if fl & 1:
            if j >= n:
                break
            mf = data[j]
            j += 1
        if fl & 2:
            if j + 2 > n:
                break
            size = int.from_bytes(data[j:j + 2], "big")
            j += 2
        if fl & 4:
            if j >= n:
                break
            proto = data[j]
            j += 1
        if fl & 8:
            # 6.32-6.40 format: bit 0x8 = a 1-byte PORT (the 5.27-6.30 format had an 8-byte u64 dest
            # here, which mis-tiled the stream the moment a host set this bit). (Bit 0x10 is
            # rejected by the high-nibble guard above and never appears on this title, so it is not
            # tiled here - relaxing that guard would risk mis-parsing padding for no live benefit.)
            if j + 1 > n:
                break
            j += 1                      # destination port (1 byte)
        if size is None or j + size > n:
            break
        msgs.append(Message(flags=fl, msgflags=mf, proto=proto, size=size,
                            payload=data[j:j + size], hdr_bytes=data[hdr_start:j]))
        i = j + size
    return msgs, i


def build_message(proto, payload, msgflags=None):
    """Build a self-contained message header (all fields present, no inheritance) + payload.
    flags bit0=msgflags bit1=size bit2=proto. We always set size+proto so the message parses
    standalone; msgflags is included only when given."""
    flags = 0x02 | 0x04
    hdr = bytearray()
    if msgflags is not None:
        flags |= 0x01
    hdr.append(flags)
    if msgflags is not None:
        hdr.append(msgflags & 0xFF)
    hdr += len(payload).to_bytes(2, "big")
    hdr.append(proto & 0xFF)
    return bytes(hdr) + payload


@dataclass
class Reliable:
    flagsA: int
    seq: int
    ack: int
    payload: bytes
    raw_len: int = 0

    def serialize(self):
        ln = len(self.payload)
        return (bytes([self.flagsA, 0x00, ln])
                + self.seq.to_bytes(2, "big") + self.ack.to_bytes(2, "big")
                + bytes([0x00]) + self.payload)


def parse_reliable(payload):
    """Reliable(10) 8-byte sub-header then inner payload[len]."""
    if len(payload) < 8:
        return None
    ln = payload[2]
    return Reliable(flagsA=payload[0],
                    seq=int.from_bytes(payload[3:5], "big"),
                    ack=int.from_bytes(payload[5:7], "big"),
                    payload=payload[8:8 + ln], raw_len=ln)


def build_reliable(seq, ack, inner, flagsA=FLAGSA_GBA):
    return Reliable(flagsA=flagsA, seq=seq, ack=ack, payload=inner).serialize()


def parse_app(data):
    """Full application blob -> (messages, station_id_or_None, tail_len). The trailing region
    after the last message is a 2-byte station-id footer then 0xff padding."""
    msgs, consumed = parse_messages(data)
    tail = data[consumed:]
    stripped = tail.rstrip(b"\xff")
    station = int.from_bytes(stripped, "big") if len(stripped) == 2 else None
    return msgs, station, len(tail)


def build_app(messages, station_id=STATION_HOST, pad=0):
    """Concatenate built message bytes + the 2-byte station-id footer (+ optional 0xff pad). Default
    footer = STATION_HOST (the recipient of a guest->host blob)."""
    blob = b"".join(messages) + station_id.to_bytes(2, "big")
    return blob + b"\xff" * pad
