"""GBA Gen-3 (international/English) character map - encode/decode names.

Mon nicknames/OT names inside a .pk3 are already stored in this charmap, so injecting a
mon needs no re-encoding. We need encode() only for the SIM's own LinkPlayer OT name and
trainer-card text, which we build from a Python string (link.c InitLocalLinkPlayer). decode()
mirrors the name decoder used elsewhere for display. Terminator = 0xFF; padding after the terminator is also
0xFF (FRLG name fields are fixed width, 0xFF-filled).
"""

EOS = 0xFF
PAD = 0xFF

# Decode table: byte -> ASCII. Covers the printable range used by English names. Punctuation values
# verified against the decomp charmap.txt: 0xAD='.', 0xAE='-', 0xAF='·', 0xB0='…', 0xB7='¥', 0xB9='×',
# 0xBA='/'. The old table had 0xAD/0xAE/0xB0/0xBA wrong + was missing 0xAF/0xB7/0xB9 - WIRE-AFFECTING via
# encode() (the LinkPlayer name + NI uname) for any OT name with . - / · … ¥ ×.
_DEC = {0x00: " ", 0xAD: ".", 0xAE: "-", 0xAF: "·", 0xB0: "…",
        0xB7: "¥", 0xB9: "×", 0xBA: "/", 0xB1: "“", 0xB2: "”",
        0xB3: "‘", 0xB4: "’", 0xB5: "♂", 0xB6: "♀", 0xB8: ",",
        0xAB: "!", 0xAC: "?"}
for _i in range(10):
    _DEC[0xA1 + _i] = "0123456789"[_i]
for _i in range(26):
    _DEC[0xBB + _i] = chr(ord("A") + _i)   # 0xBB..0xD4 = A..Z
    _DEC[0xD5 + _i] = chr(ord("a") + _i)   # 0xD5..0xEE = a..z

# Encode table is the inverse (first byte wins for any duplicate glyphs).
_ENC = {}
for _b, _c in _DEC.items():
    _ENC.setdefault(_c, _b)


def decode(b, stop_at_eos=True):
    """GBA name bytes -> str. Stops at the 0xFF terminator by default."""
    out = []
    for x in b:
        if x == EOS:
            if stop_at_eos:
                break
            continue
        out.append(_DEC.get(x, "."))
    return "".join(out)


def encode(s, width=None, pad=PAD):
    """str -> GBA name bytes. If `width` is given, append the 0xFF terminator then `pad` to
    exactly `width` bytes. Mon nickname/OT fields pad with 0xFF (pad=0xFF, the default); the
    struct LinkPlayer `name` field pads with 0x00 after the terminator (pad=0x00), matching
    InitLocalLinkPlayer over a zero-initialised struct. Unknown chars are dropped."""
    out = bytearray()
    for ch in s:
        if ch in _ENC:
            out.append(_ENC[ch])
    if width is not None:
        out = out[:width - 1] if width else out
        out.append(EOS)
        while len(out) < width:
            out.append(pad)
        out = out[:width]
    return bytes(out)
