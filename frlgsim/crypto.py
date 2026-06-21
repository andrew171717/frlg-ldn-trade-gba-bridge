"""Pia AES-GCM transport crypto for FRLG LDN (the bottom encryption layer).

Recipe (NintendoClients wiki "Pia Protocol"/"Pia Game Keys", LDN 6.16-6.42), LOCKED against
the reference capture via GCM-tag verification:

    session_key = AES_ECB(game_key, ssid)           # ssid is one 16-byte block
    net_id      = CRC32(ssid[1:16])
    GCM nonce   = (net_id XOR src_ip_be)(4) || header_nonce(8)     # variant "nid_be^ip"
    AAD         = empty                              # locked: aad=none
    tag         = first 8 bytes of the GCM tag, no ciphertext trim

Packet header (Pia 6.32-7.2), 29 bytes:
    [0:4]  magic 32 AB 98 64
    [4]    enc/version (0x90 = encrypted v? on this title)
    [5]    flags (per-packet Pia transport flags; compression bit etc. - live-tunable)
    [6:8]  dst variable-station id (BE)   7620 joiner / c493 host
    [8:10] src variable-station id (BE)
    [10:12] packet id (BE)
    [12]   footer size (= 2: the 2-byte RECIPIENT/destination station-id footer inside the payload;
           for broadcast it is a recipient list) (it is the recipient, not the sender)
    [13:21] 8-byte header nonce
    [21:29] 8-byte (truncated) GCM tag
    [29:]  ciphertext

The payload, once decrypted, is optionally a zstd frame (Pia_ZStandard, stock, no dict);
decompress() peels it. The decompressed application blob is what reliable.py parses.
"""

import zlib
from dataclasses import dataclass
from Crypto.Cipher import AES

try:
    import zstandard as _zstd
except ImportError:                      # pragma: no cover
    _zstd = None

# The host's Pia messages are zstd-compressed; without this module decompress() silently no-ops
# and every received message is unparseable (the sim then never responds). Callers should verify.
HAVE_ZSTD = _zstd is not None

FRLG_GAME_KEY = bytes.fromhex("83ca7fab734c34633b10183526c1e85b")
PIA_MAGIC = bytes.fromhex("32ab9864")
ZSTD_MAGIC = bytes.fromhex("28b52ffd")
HDR = 29
NONCE_OFF, TAG_OFF, CT_OFF = 13, 21, 29

# Pia variable-station ids observed on this title (BE u16). reference capture: HOST var=0x7620, JOINER var=0xc493.
# These were SWAPPED - latent because the live path LEARNS both from the Net 0x11 wire, but
# the constants/PiaHeader defaults were wrong for replay / any new caller.
STATION_HOST = 0x7620     # the Switch host / 169.254.x.1
STATION_JOINER = 0xc493   # the joiner / 169.254.x.2


@dataclass
class PiaHeader:
    """The 29-byte plaintext header. `enc`/`flags`/`footer` default to the joiner's
    observed steady-state values so a generated packet looks authentic; override for an
    exact replay of a captured packet."""
    dst: int = STATION_HOST
    src: int = STATION_JOINER
    pktid: int = 0
    nonce8: bytes = b"\x00" * 8
    enc: int = 0x90
    flags: int = 0x50
    footer: int = 2

    def pack(self):
        return (PIA_MAGIC
                + bytes([self.enc, self.flags])
                + self.dst.to_bytes(2, "big")
                + self.src.to_bytes(2, "big")
                + self.pktid.to_bytes(2, "big")
                + bytes([self.footer])
                + self.nonce8)

    @classmethod
    def unpack(cls, datagram):
        return cls(
            enc=datagram[4], flags=datagram[5],
            dst=int.from_bytes(datagram[6:8], "big"),
            src=int.from_bytes(datagram[8:10], "big"),
            pktid=int.from_bytes(datagram[10:12], "big"),
            footer=datagram[12], nonce8=datagram[NONCE_OFF:TAG_OFF],
        )


def ip_bytes(ip):
    """'169.254.21.2' -> b'\\xa9\\xfe\\x15\\x02'."""
    if isinstance(ip, (bytes, bytearray)):
        return bytes(ip)
    return bytes(int(x) for x in ip.split("."))


def is_pia(datagram):
    return len(datagram) >= CT_OFF and datagram[:4] == PIA_MAGIC


def decompress(plaintext):
    """Peel the optional Pia zstd frame. Returns (app_bytes, was_compressed). The streaming
    decompressor stops at the frame end, so trailing 0xff packet padding is ignored."""
    if plaintext[:4] != ZSTD_MAGIC or _zstd is None:
        return plaintext, False
    try:
        return _zstd.ZstdDecompressor().decompressobj().decompress(plaintext), True
    except Exception:
        return plaintext, False


def _to_window_frame(frame, wd=0x18):
    """Normalise a zstd frame header to the exact WINDOW-DESCRIPTOR form the Switch emits: FHD
    `0x00` + a fixed 1-byte window descriptor `0x18` (8 KiB window), matching the reference capture byte-for-byte
    (`28b52ffd 00 18 ...`). python-zstandard emits either a single-segment header (FHD `0x20`, no
    window descriptor) or a window-descriptor header with a smaller window (e.g. `0x00` -> 1 KiB);
    both have identical compressed blocks. We only ever WIDEN the declared window (8 KiB >= any
    back-reference distance, since Pia packets are < 1.5 KiB), so the frame still decodes to the
    same bytes. Frames with a dictionary id or content checksum are left untouched (never our case)."""
    if frame[:4] != ZSTD_MAGIC:
        return frame
    fhd = frame[4]
    if (fhd & 0x03) or (fhd & 0x04):                 # dict-id / content-checksum: leave as-is
        return frame
    fcs_flag = fhd >> 6
    if fhd & 0x20:                                    # single-segment: FCS present, no window desc
        blocks = frame[5 + ((1, 2, 4, 8)[fcs_flag]):]
    else:                                             # window-descriptor (1 B) + optional FCS
        if frame[5] > wd:                            # encoder already chose a wider window: keep it
            return frame
        blocks = frame[6 + ((0, 2, 4, 8)[fcs_flag]):]
    return ZSTD_MAGIC + bytes([0x00, wd]) + blocks


ZSTD_LEVEL = 4               # Pia uses zstd LEVEL 4. VERIFIED byte-identical: decompress every compressed
                             # frame in the reference captures, recompress at level 4 + _to_window_frame ->
                             # 100% match to the real Switch HOST (5267/5267 + 5552/5552) AND both clients
                             # (reference capture PC 1031/1031, Ryujinx 1426/1426). Our old default (level 3) matched the
                             # host only 98.8%; level 4 is exact. (level 2=98.5, 5=96, 6+=<95.)


def compress(app_bytes):
    """Wrap an application blob in a zstd frame matching the console BYTE-FOR-BYTE: zstd LEVEL 4,
    window-descriptor header (28b52ffd 00 18 ...), no content-size/checksum. The compressed payload
    is then 0xFF-padded by the caller to a multiple of 16 before encryption [wiki Pia 6.32+; verified
    byte-identical vs the reference captures' host+client frames]."""
    if _zstd is None:
        raise RuntimeError("zstandard module not available")
    return _to_window_frame(
        _zstd.ZstdCompressor(level=ZSTD_LEVEL, write_content_size=False).compress(app_bytes))


class PiaCrypto:
    """Holds the session key derived from the LDN SSID and does GCM both ways."""

    def __init__(self, ssid, game_key=FRLG_GAME_KEY):
        self.ssid = bytes(ssid)
        self.session_key = AES.new(game_key, AES.MODE_ECB).encrypt(self.ssid)
        self.net_id = zlib.crc32(self.ssid[1:16]) & 0xFFFFFFFF

    def nonce(self, src_ip, header_nonce8):
        four = (self.net_id ^ int.from_bytes(ip_bytes(src_ip), "big")) & 0xFFFFFFFF
        return four.to_bytes(4, "big") + bytes(header_nonce8)

    def decrypt(self, datagram, src_ip):
        """datagram = full Pia UDP payload, src_ip = the SENDER's LDN ip. Returns the raw
        plaintext (still zstd-wrapped if it was compressed) or None on auth failure."""
        if not is_pia(datagram):
            return None
        nonce = self.nonce(src_ip, datagram[NONCE_OFF:TAG_OFF])
        tag = datagram[TAG_OFF:CT_OFF]
        ct = datagram[CT_OFF:]
        c = AES.new(self.session_key, AES.MODE_GCM, nonce=nonce, mac_len=len(tag))
        try:
            return c.decrypt_and_verify(ct, tag)
        except ValueError:
            return None

    def encrypt(self, plaintext, src_ip, header):
        """Build a full Pia UDP datagram. `header` is a PiaHeader (its nonce8 is used as the
        GCM header-nonce; randomise it per packet for live, or copy a captured one to replay).
        AAD is empty (locked)."""
        nonce = self.nonce(src_ip, header.nonce8)
        c = AES.new(self.session_key, AES.MODE_GCM, nonce=nonce, mac_len=8)
        ct, tag = c.encrypt_and_digest(plaintext)
        return header.pack() + tag + ct
