#!/usr/bin/env python3
"""Decode an LDN advertisement payload and show how it maps onto the GBA RFU beacon struct.

Prints every RFU beacon field, where it comes from in the advertisement, and its value,
with "None" for fields the advertisement drops.

An advertisement payload is [ Pia system header (0x5C bytes) ][ game payload (30 bytes) ]; this tool
skips the header. The game payload is a 24-byte RFU beacon record obfuscated with a custom base85
(24 bytes -> 30 chars). That record is a repack of the beacon librfu broadcasts via
rfu_REQ_configGameData: the game-name "gname" struct + user name (pokefirered decomp:
include/link_rfu.h, include/librfu.h, src/librfu_rfu.c). The repack drops a few fields and one version
bit, which show as "None".

24-byte record layout:
    [0x00:0x02] player trainer id     u16 LE
    [0x02:0x0A] user name             8 bytes, GBA character set
    [0x0A:0x0C] RFU id / session id   u16 LE   (the parent id a child connects to)
    [0x0C:0x10] partner info          4 bytes  (one summary byte per child slot)
    [0x10:0x14] packed game data      u32 LE   (bit-repacked gname fields; see PACKED_BITS)
    [0x14:0x18] trade species word    u32 LE   (species = (word >> 16) & 0x3FF)

Run: python3 utils/rfu_advert_map.py <hex>   (or pipe the hex on stdin)
"""

import argparse
import sys

PIA_HEADER_LEN = 0x5C        # size of the Pia system header that precedes the game payload
RECORD_LEN = 0x18            # the RFU beacon record is 24 bytes (-> 30 base85 chars)


# --------------------------------------------------------------------------------------------------
# 1. The custom base85 that obfuscates the game payload (emulator-specific, not in the decomp).
#    Alphabet = ASCII 0x23..0x78 with 0x5C ('\') skipped; first char of each 5-char group is the low
#    digit; the 32-bit value is little-endian. 5 chars -> 4 bytes.
# --------------------------------------------------------------------------------------------------
def base85_decode(chars):
    if len(chars) % 5 != 0:
        raise ValueError(f"base85 length {len(chars)} is not a multiple of 5")
    out = bytearray()
    for i in range(0, len(chars), 5):
        value = 0
        for c in reversed(chars[i:i + 5]):          # reversed: first char is the low digit
            if not (0x23 <= c <= 0x78) or c == 0x5C:
                raise ValueError(f"byte {c:#04x} is not in the base85 alphabet (0x23..0x78 minus 0x5c)")
            digit = c - 0x23 if c < 0x5C else c - 0x24    # 0x5c is skipped, so shift down past it
            value = value * 85 + digit
        out += (value & 0xFFFFFFFF).to_bytes(4, "little")
    return bytes(out)


# --------------------------------------------------------------------------------------------------
# 2. The GBA character set, enough to render the user name (pokefirered charmap.txt).
# --------------------------------------------------------------------------------------------------
def frlg_text(raw):
    chars = []
    for x in raw:
        if x == 0xFF:                               # end-of-string terminator
            break
        if 0xBB <= x <= 0xD4:
            chars.append(chr(ord("A") + x - 0xBB))
        elif 0xD5 <= x <= 0xEE:
            chars.append(chr(ord("a") + x - 0xD5))
        elif 0xA1 <= x <= 0xAA:
            chars.append(chr(ord("0") + x - 0xA1))
        elif x == 0x00:
            chars.append(" ")
        else:
            chars.append("?")
    return "".join(chars).rstrip()


# --------------------------------------------------------------------------------------------------
# 3. Enums for readable values (pokefirered include/constants/global.h; activities in union_room.h).
# --------------------------------------------------------------------------------------------------
LANGUAGES = {1: "Japanese", 2: "English", 3: "French", 4: "Italian", 5: "German",
             6: "Korean(unused)", 7: "Spanish"}
# version = GAME_VERSION. Only wireless-adapter games broadcast a beacon (Emerald/FireRed/LeafGreen);
# Ruby/Sapphire (1/2) are speculative - expected only via their Switch ports' backported wireless. Only
# the low 3 bits survive the repack (0..7); other values print raw.
VERSIONS = {1: "Sapphire", 2: "Ruby", 3: "Emerald", 4: "FireRed", 5: "LeafGreen"}
SPECULATIVE_VERSIONS = {1, 2}
GENDERS = {0: "Male", 1: "Female"}
ACTIVITIES = {0: "NONE", 1: "BATTLE_SINGLE", 2: "BATTLE_DOUBLE", 3: "BATTLE_MULTI", 4: "TRADE",
              5: "CHAT", 8: "CARD", 9: "POKEMON_JUMP", 10: "BERRY_CRUSH", 11: "BERRY_PICK",
              12: "SEARCH", 13: "SPIN_TRADE", 14: "ITEM_TRADE", 15: "RECORD_CORNER",
              16: "BERRY_BLENDER", 21: "WONDER_CARD", 22: "WONDER_NEWS"}
IN_UNION_ROOM = 1 << 6                              # bit 6 of the 7-bit activity field


def label(value, table):
    name = table.get(value)
    return f"{value} ({name})" if name else str(value)


def activity_label(value):
    base = value & (IN_UNION_ROOM - 1)              # low 6 bits = the activity itself
    text = label(base, ACTIVITIES)
    if value & IN_UNION_ROOM:
        text += " | IN_UNION_ROOM"
    return text


def version_label(value):
    name = VERSIONS.get(value)
    if not name:
        return str(value)
    if value in SPECULATIVE_VERSIONS:               # Ruby/Sapphire only via the expected Switch backport
        return f"{value} ({name}, speculative - Switch-port backport)"
    return f"{value} ({name})"


# --------------------------------------------------------------------------------------------------
# 4. Bit layout of the packed game-data u32 at record[0x10:0x14]: field -> (low bit, width). The
#    emulator's repack of the RfuGameData fields (pokefirered include/link_rfu.h).
# --------------------------------------------------------------------------------------------------
PACKED_BITS = {
    "activity":          (0, 7),
    "playerGender":      (7, 1),
    "version":           (8, 3),                    # NOTE: only 3 of the 4 gname version bits
    "language":          (11, 4),
    "startedActivity":   (15, 1),
    "canLinkNationally": (16, 1),
    "hasNationalDex":    (17, 1),
    "tradeType":         (18, 6),
    "gameClear":         (24, 1),
    "tradeLevel":        (25, 7),
}


def bits(word, lo, width):
    return (word >> lo) & ((1 << width) - 1)


def decode_record(record):
    """Turn the 24-byte record into a dict of decoded values."""
    packed = int.from_bytes(record[0x10:0x14], "little")
    species_word = int.from_bytes(record[0x14:0x18], "little")
    r = {
        "player_tid":    int.from_bytes(record[0x00:0x02], "little"),
        "uname_bytes":   record[0x02:0x0A],
        "rfu_id":        int.from_bytes(record[0x0A:0x0C], "little"),
        "partner_info":  record[0x0C:0x10],
        "trade_species": bits(species_word, 16, 10),
    }
    for name, (lo, width) in PACKED_BITS.items():
        r[name] = bits(packed, lo, width)
    return r


# --------------------------------------------------------------------------------------------------
# 5. The mapping table: one row per RFU beacon field (name, C type, advertisement source, value).
#    source=None => the advertisement omits it, so it prints as "None". Fields: RfuTgtData in
#    pokefirered include/librfu.h, RfuGameData (gname) in include/link_rfu.h.
# --------------------------------------------------------------------------------------------------
def build_rows(r):
    def src(bit_name):
        lo, width = PACKED_BITS[bit_name]
        hi = lo + width - 1
        return f"record[0x10:0x14] bit {lo}" + ("" if width == 1 else f"-{hi}")

    return [
        # --- RfuTgtData header ---
        ("RfuTgtData.id",                     "u16",   "record[0x0A:0x0C]", f"0x{r['rfu_id']:04x}"),
        ("RfuTgtData.slot",                   "u8",    None,                None),
        ("RfuTgtData.mbootFlag",              "u8",    None,                None),
        ("RfuTgtData.serialNo",               "u16",   None,                None),
        # --- gname.compatibility (a u16 of bitfields) ---
        ("gname.compat.language",             "u16:4", src("language"),      label(r["language"], LANGUAGES)),
        ("gname.compat.hasNews",              "u16:1", None,                None),
        ("gname.compat.hasCard",              "u16:1", None,                None),
        ("gname.compat.unknown",              "u16:1", None,                None),
        ("gname.compat.canLinkNationally",    "u16:1", src("canLinkNationally"), r["canLinkNationally"]),
        ("gname.compat.hasNationalDex",       "u16:1", src("hasNationalDex"), r["hasNationalDex"]),
        ("gname.compat.gameClear",            "u16:1", src("gameClear"),     r["gameClear"]),
        ("gname.compat.version",              "u16:4", src("version") + " (top bit dropped)",
                                                                            version_label(r["version"])),
        ("gname.compat.unused",               "u16:2", None,                None),
        # --- gname body ---
        ("gname.playerTrainerId",             "u16",   "record[0x00:0x02]", f"0x{r['player_tid']:04x}"),
        ("gname.partnerInfo[4]",              "u8[4]", "record[0x0C:0x10]", r["partner_info"].hex()),
        ("gname.tradeSpecies",                "u16:10", "record[0x14:0x18] bit 16-25", r["trade_species"]),
        ("gname.tradeType",                   "u16:6", src("tradeType"),    r["tradeType"]),
        ("gname.activity",                    "u8:7",  src("activity"),     activity_label(r["activity"])),
        ("gname.startedActivity",             "u8:1",  src("startedActivity"), r["startedActivity"]),
        ("gname.playerGender",                "u8:1",  src("playerGender"), label(r["playerGender"], GENDERS)),
        ("gname.tradeLevel",                  "u8:7",  src("tradeLevel"),   r["tradeLevel"]),
        ("gname.padding",                     "u8",    None,                None),
        # --- user name ---
        ("uname",                             "u8[8]", "record[0x02:0x0A]",
                                                       f"{frlg_text(r['uname_bytes'])!r}  ({r['uname_bytes'].hex()})"),
    ]


def print_table(rows):
    header = ("RFU beacon field", "type", "advertisement source", "value")
    OMITTED = "— (not carried)"                # em dash
    table = [header]
    for field, ctype, source, value in rows:
        table.append((field, ctype,
                      source if source is not None else OMITTED,
                      "None" if value is None else str(value)))
    widths = [max(len(row[i]) for row in table) for i in range(4)]
    for n, row in enumerate(table):
        print("  " + "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))
        if n == 0:
            print("  " + "  ".join("-" * widths[i] for i in range(4)))


# --------------------------------------------------------------------------------------------------
# 6. CLI: read the payload hex, locate the game payload, decode, print.
# --------------------------------------------------------------------------------------------------
def game_payload(raw):
    """Return the base85 game payload from a raw advertisement payload. Accepts either the bare game
    payload (length a multiple of 5) or the full application data (Pia header + game payload)."""
    if len(raw) % 5 == 0:
        return raw, f"bare {len(raw)}-byte game payload"
    if len(raw) > PIA_HEADER_LEN and (len(raw) - PIA_HEADER_LEN) % 5 == 0:
        return raw[PIA_HEADER_LEN:], (f"{len(raw) - PIA_HEADER_LEN}-byte game payload after stripping "
                                      f"the {PIA_HEADER_LEN}-byte Pia system header")
    raise ValueError(f"cannot locate the game payload in {len(raw)} bytes (expected a length that is a "
                     f"multiple of 5, or 0x5C + a multiple of 5)")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Map an LDN advertisement payload onto the RFU beacon struct.")
    ap.add_argument("payload", nargs="?", help="advertisement payload as hex (else read from stdin)")
    args = ap.parse_args(argv)

    text = args.payload if args.payload is not None else sys.stdin.read()
    hexstr = "".join(text.split()).removeprefix("0x")
    try:
        raw = bytes.fromhex(hexstr)
    except ValueError:
        ap.error("payload is not valid hex")

    try:
        payload, how = game_payload(raw)
        record = base85_decode(payload)
    except ValueError as e:
        ap.error(str(e))
    if len(record) < RECORD_LEN:
        ap.error(f"decoded {len(record)} bytes, need at least {RECORD_LEN}")
    record = record[:RECORD_LEN]

    print(f"input          : {raw.hex()}")
    print(f"interpreted as : {how}")
    print(f"decoded record : {record.hex()}  ({RECORD_LEN} bytes)")
    print()
    print_table(build_rows(decode_record(record)))


if __name__ == "__main__":
    main()
