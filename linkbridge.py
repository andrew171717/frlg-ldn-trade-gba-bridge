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
RP2040 -> Pi:  SCAN_START\\n      start continuous background LDN scanning
               SCAN_RESULT\\n     request current host list (instant reply)
               SCAN_STOP\\n       stop scanning and clear the host cache

Pi -> RP2040:  HOSTS <N>\\n       (only in response to SCAN_RESULT)
               HOST <w0> ... <w6>\\n  (N lines follow; each w is 0x-prefixed u32)
               ERR <msg>\\n       on unexpected errors

Notes:
  - SCAN_START is idempotent; sending it while already scanning is a no-op.
  - SCAN_RESULT is answered immediately with whatever the last completed scan
    found, so the RP2040 never waits for a full LDN scan to finish.
  - LDN scans take ~2-3 s each.  The background loop runs them continuously;
    hosts not seen for 3+ seconds are removed from the cache.
  - SCAN_STOP clears the cache, so the next SCAN_START begins fresh.
"""

import argparse
import logging
import sys
import threading
import time

import serial  # pyserial

log = logging.getLogger("linkbridge")


# ---------------------------------------------------------------------------
# LDN single scan
# ---------------------------------------------------------------------------

def _do_ldn_scan(phyname: str, keys_path: str) -> list[dict]:
    """Run one LDN scan; return a list of host dicts.

    Each dict contains:
      "comm_id" : int            local_communication_id
      "words"   : list[int]      7 big-endian u32 words for BroadcastReadPoll
    """
    try:
        import trio
        import ldn
        from frlgsim.transport import free_radio
    except ImportError as e:
        log.error("Missing dependency: %s — install requirements.txt", e)
        return []

    results: list[dict] = []

    async def _scan():
        keys = ldn.load_keys(keys_path)
        networks = await ldn.scan(keys, phyname=phyname)
        log.debug("[SCAN] raw: %d network(s)", len(networks))
        for n in networks:
            comm_id = getattr(n, "local_communication_id", 0)
            scene   = getattr(n, "scene_id", 0)
            num_p   = getattr(n, "num_participants", 0)
            max_p   = getattr(n, "max_participants", 0)
            app_raw = bytes(getattr(n, "application_data", b"") or b"")

            log.info(
                "[SCAN] comm_id=0x%016x scene=%d %d/%d app_data=%d B",
                comm_id, scene, num_p, max_p, len(app_raw),
            )
            # Full hex dump -- lets us verify the offset and byte order.
            log.info("[SCAN] app_raw: %s", app_raw.hex())

            # Extract GBA emulator payload from Pia beacon (0x5C-byte header).
            # Words 0-5 = 6 × u32 big-endian from the payload.
            # Word 6    = TBD (0 until confirmed from a real adapter capture).
            if len(app_raw) >= 0x5C:
                gba_payload = app_raw[0x5C:]
            else:
                log.warning("[SCAN] app_data too short (0x%x B), using raw", len(app_raw))
                gba_payload = app_raw

            words = [0] * 7
            for i in range(6):
                off = i * 4
                if off + 4 <= len(gba_payload):
                    # The GBA is little-endian (ARM7); NSO stores each 32-bit
                    # word in native LE byte order in the LDN app_data field.
                    # Reading as little-endian recovers the original word value
                    # so that the SPI TX FIFO sends it MSB-first and the GBA
                    # receives exactly what the emulated FRLG game produced.
                    words[i] = int.from_bytes(gba_payload[off:off + 4], "little")
                else:
                    words[i] = 0x80000000  # filler if payload is shorter than expected
            # words[6]: slot index placeholder; overwritten with 1-based slot
            # by the caller (_send_hosts) once we know which slot this host occupies.

            log.info("[SCAN] -> gba_payload raw (%d B): %s",
                     len(gba_payload), gba_payload.hex())
            log.info("[SCAN] -> words: %s", " ".join(f"0x{w:08x}" for w in words))
            results.append({"comm_id": comm_id, "words": words})

    free_radio({phyname}, log.info)
    try:
        trio.run(_scan)
    except BaseException as e:
        log.error("[SCAN] ldn.scan() raised: %s", e)

    return results


# ---------------------------------------------------------------------------
# Continuous background scanner
# ---------------------------------------------------------------------------

class ScanManager:
    """Runs LDN scans continuously in a background thread.

    The host cache is updated after each completed scan.  Entries not seen
    for 3+ seconds are pruned so that hosts that stopped broadcasting disappear.

    Thread safety: all state protected by self._lock.
    """

    _HOST_EXPIRY_S = 3.0  # remove a host if not seen for this many seconds

    def __init__(self, phyname: str, keys_path: str) -> None:
        self._phyname   = phyname
        self._keys_path = keys_path
        self._lock      = threading.Lock()
        self._active    = False
        # Cache entries: {"comm_id": int, "words": list[int], "last_seen": float}
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
            log.info("[SCAN] scan mode started")

    def stop(self) -> None:
        """Exit scan mode and clear the host cache."""
        with self._lock:
            self._active = False
            self._hosts.clear()
        log.info("[SCAN] scan mode stopped; cache cleared")

    def get_hosts(self) -> list[dict]:
        """Return up to 4 currently valid host entries."""
        now = time.monotonic()
        with self._lock:
            valid = [h for h in self._hosts if now - h["last_seen"] < self._HOST_EXPIRY_S]
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

            # Run one LDN scan (~2-3 s).
            t0 = time.monotonic()
            new_hosts = _do_ldn_scan(self._phyname, self._keys_path)
            elapsed = time.monotonic() - t0
            log.debug("[SCAN] scan took %.2f s, found %d host(s)", elapsed, len(new_hosts))

            now = time.monotonic()
            with self._lock:
                if not self._active:
                    # stop() was called while we were scanning; discard results.
                    continue

                # Prune stale entries.
                self._hosts = [
                    h for h in self._hosts
                    if now - h["last_seen"] < self._HOST_EXPIRY_S
                ]

                # Update existing entries or append new ones.
                index = {h["comm_id"]: i for i, h in enumerate(self._hosts)}
                for h in new_hosts:
                    entry = {"comm_id": h["comm_id"], "words": h["words"], "last_seen": now}
                    if h["comm_id"] in index:
                        self._hosts[index[h["comm_id"]]] = entry
                    else:
                        self._hosts.append(entry)

            # Wait 1 second before the next scan.
            time.sleep(1.0)


# ---------------------------------------------------------------------------
# Serial I/O helpers
# ---------------------------------------------------------------------------

def _send(port: serial.Serial, line: str) -> None:
    data = (line + "\n").encode("ascii", errors="replace")
    port.write(data)
    port.flush()
    log.debug("TX: %r", line)


def _send_hosts(port: serial.Serial, hosts: list[dict]) -> None:
    """Send a HOSTS/HOST response block for the given host list."""
    _send(port, f"HOSTS {len(hosts)}")
    for slot, h in enumerate(hosts, start=1):
        words = list(h["words"])
        words[6] = slot   # real adapter uses 1-based slot index for word[6]
        words_str = " ".join(f"0x{w:08x}" for w in words)
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
