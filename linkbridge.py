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

Pi -> RP2040:  HOSTS <N>\\n       (only in response to SCAN_RESULT)
               HOST <w0> ... <w6>\\n  (N lines; 7 LE u32 words, GBA 0x1D format)
               ERR <msg>\\n       on unexpected errors

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

import serial  # pyserial

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
            from frlgsim.transport import free_radio
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

                rfutgt = app_raw[RFU_TGT_DATA_OFFSET :
                                 RFU_TGT_DATA_OFFSET + RFU_TGT_DATA_LEN]

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
# Serial I/O helpers
# ---------------------------------------------------------------------------

def _send(port: serial.Serial, line: str) -> None:
    data = (line + "\n").encode("ascii", errors="replace")
    port.write(data)
    port.flush()
    log.debug("TX: %r", line)


def _rfutgt_to_words(rfutgt: bytes) -> list:
    """Convert a 30-byte RfuTgtData struct (from the LDN beacon) to 7 LE u32 words
    in the GBA wireless adapter 0x1D BroadcastReadPoll per-host format (28 bytes).

    RfuTgtData layout (librfu.h):
      [0:2]  id (u16 LE)      — host RFU id; passed through to the GBA child
      [2]    slot             — passed through
      [3]    mbootFlag        — ZEROED (must be 0 in the 0x1D response)
      [4:6]  serialNo         — 0x0002 for FRLG; passed through
      [6:19] gname[0:13]      — plaintext RfuGameData struct
      [19]   gname[13]        — ~checksum; already valid, computed by host GBA
      [20]   gname[14]        — 0x00 PADDING; SKIPPED in the 0x1D format
      [21:30] uname[0:9]      — GBA charmap trainer name; first 8 bytes used

    The 0x1D format is 28 bytes; uname starts at byte 20, immediately after the
    checksum — so rfutgt[20] (gname[14] padding) must be skipped and uname taken
    from rfutgt[21:29].

    The checksum at rfutgt[19] was computed by the host GBA as:
      ~(sum(gname[0:8]) + sum(uname[0:8])) & 0xFF
    It is already correct for the received gname and uname bytes — we pass it
    through unchanged. No re-computation needed.
    """
    assert len(rfutgt) >= 30, f"RfuTgtData too short: {len(rfutgt)}"
    pkt = bytearray(28)
    pkt[0:2]   = rfutgt[0:2]    # id
    pkt[2]     = rfutgt[2]      # slot
    pkt[3]     = 0              # mbootFlag → 0
    pkt[4:6]   = rfutgt[4:6]   # serialNo
    pkt[6:20]  = rfutgt[6:20]  # gname[0:13] + checksum (bytes 6-19 of RfuTgtData)
    pkt[20:28] = rfutgt[21:29] # uname[0:8] — skip rfutgt[20] (gname[14] padding)
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
    scanner = ScanManager(phyname, keys_path)

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
