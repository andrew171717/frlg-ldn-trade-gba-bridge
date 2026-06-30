#!/usr/bin/env python3
"""linkbridge.py — Serial bridge: RP2040-Zero <-> Raspberry Pi LDN stack.

Run this on the Raspberry Pi (or Milk-V) while the RP2040-Zero is plugged into
the GBA and connected to this board via GPIO wires.

Hardware wiring
---------------
RP2040-Zero                   Raspberry Pi / Milk-V
  GPIO0 (UART0 TX)   -------> GPIO15 / pin 22  (RX / ttyAMA0)
  GPIO1 (UART0 RX)   <------- GPIO14 / pin 8   (TX / ttyAMA0)
  GND                -------> any GND pin

Pi UART setup (Raspberry Pi 3/4/5):
  The primary UART (/dev/ttyAMA0) is grabbed by Bluetooth on Pi 3+.
  Either disable BT (add "dtoverlay=disable-bt" to /boot/config.txt and reboot)
  or use the secondary UART /dev/ttyS0.  Milk-V: use the appropriate /dev/ttyS*.

  Also add "enable_uart=1" to /boot/config.txt so the UART pins are exposed.

Run as root (required for ldn.scan() -> nl80211 / raw sockets):
  sudo python3 linkbridge.py [--port /dev/ttyAMA0] [--baud 115200] [--phy phy0]

Protocol (line-based ASCII, \n terminated)
-------------------------------------------
RP2040 -> Pi:  SCAN\n
Pi -> RP2040:  HOSTS <N>\n           (N = 0..4 host entries found)
               HOST <w0> <w1> <w2> <w3> <w4> <w5> <w6>\n   (N of these follow)

Each word is a 32-bit hex value prefixed with 0x (e.g. 0x80000000).
Words 0..5 are the 6 Broadcast (0x16) payload words the remote host sent when it
called Broadcast on its own wireless adapter; word 6 is reserved / TBD (sent as
0x00000000 until we confirm the real GBA adapter's encoding from a capture).

On error:
Pi -> RP2040:  ERR <message>\n
"""

import argparse
import logging
import sys
import time

import serial  # pyserial

log = logging.getLogger("linkbridge")


# ---------------------------------------------------------------------------
# LDN scan
# ---------------------------------------------------------------------------

def _do_ldn_scan(phyname: str, keys_path: str) -> list[dict]:
    """Run a one-shot LDN scan and return a list of host dicts.

    Each dict has:
      "app_data"  : bytes | None   — raw application_data from the LDN beacon
      "comm_id"   : int            — local_communication_id
      "scene_id"  : int
      "players"   : (num, max)
      "words"     : list[int]      — 7 big-endian 32-bit words for BroadcastReadEnd

    Requires root (nl80211 raw socket).
    """
    try:
        import trio
        import ldn
        from frlgsim.transport import free_radio, GBA_APP_PASSPHRASE
    except ImportError as e:
        log.error("Missing dependency: %s — install requirements.txt", e)
        return []

    results: list[dict] = []

    async def _scan():
        keys = ldn.load_keys(keys_path)
        log.info("LDN scan started on %s", phyname)
        networks = await ldn.scan(keys, phyname=phyname)
        log.info("LDN scan found %d network(s)", len(networks))
        for n in networks:
            comm_id = getattr(n, "local_communication_id", 0)
            scene   = getattr(n, "scene_id", 0)
            num_p   = getattr(n, "num_participants", 0)
            max_p   = getattr(n, "max_participants", 0)
            policy  = getattr(n, "accept_policy", "?")
            app_raw = bytes(getattr(n, "application_data", b"") or b"")

            log.info(
                "  network comm_id=0x%016x scene=%d %d/%d policy=%s app_data=%d B",
                comm_id, scene, num_p, max_p, policy, len(app_raw),
            )
            if app_raw:
                log.debug("  app_data hex: %s", app_raw.hex())

            # Extract the GBA emulator payload from the Pia beacon.
            # The Pia system header is 0x5C bytes; the emulator-specific data follows.
            # This is the "Sloop-obfuscated RfuTgtData" that the host GBA would have
            # sent via Broadcast (0x16) — 6 words × 4 bytes = 24 bytes minimum.
            # We log the raw bytes here so we can compare against a real adapter's
            # BroadcastReadEnd capture and identify the exact word layout.
            gba_payload = b""
            if len(app_raw) >= 0x5C:
                gba_payload = app_raw[0x5C:]
                log.info("  GBA emulator payload (%d B): %s", len(gba_payload), gba_payload.hex())
            else:
                log.warning("  app_data too short for Pia header (0x%x B), using raw", len(app_raw))
                gba_payload = app_raw

            # Build the 7 words for BroadcastReadEnd (0x1E).
            # Format is still being confirmed from hardware captures:
            #   words[0..5] = the 6 Broadcast payload words from the host
            #   words[6]    = TBD (reserved 0 until we confirm from a capture)
            #
            # The gba_payload is 30 B in the reference capture.  The first 24 bytes
            # (6 × u32 big-endian) are a candidate for the Broadcast words. If that
            # turns out to be wrong, the full hex logged above tells us what to use.
            words = [0] * 7
            for i in range(6):
                offset = i * 4
                if offset + 4 <= len(gba_payload):
                    words[i] = int.from_bytes(gba_payload[offset:offset + 4], "big")
                else:
                    words[i] = 0x80000000  # filler / not enough data
            words[6] = 0x00000000  # TBD

            log.info(
                "  -> BroadcastReadEnd words: %s",
                " ".join(f"0x{w:08x}" for w in words),
            )

            results.append({
                "app_data": app_raw or None,
                "comm_id":  comm_id,
                "scene_id": scene,
                "players":  (num_p, max_p),
                "words":    words,
            })

    free_radio({phyname}, log.info)
    try:
        trio.run(_scan)
    except BaseException as e:
        log.error("LDN scan failed: %s", e)

    return results


# ---------------------------------------------------------------------------
# Protocol helpers
# ---------------------------------------------------------------------------

def _send(port: serial.Serial, line: str) -> None:
    """Send a line (with trailing newline) over the serial port."""
    data = (line + "\n").encode("ascii")
    port.write(data)
    port.flush()
    log.debug("TX: %s", line)


def _handle_scan(port: serial.Serial, phyname: str, keys_path: str) -> None:
    """Run a scan and send the result back to the RP2040."""
    log.info("SCAN command received — running LDN scan")
    t0 = time.monotonic()

    hosts = _do_ldn_scan(phyname, keys_path)
    # Cap at 4 entries: real adapter only reports up to 4 nearby games.
    hosts = hosts[:4]

    elapsed = time.monotonic() - t0
    log.info("Scan done in %.2f s — %d host(s) to report", elapsed, len(hosts))

    _send(port, f"HOSTS {len(hosts)}")
    for h in hosts:
        words_str = " ".join(f"0x{w:08x}" for w in h["words"])
        _send(port, f"HOST {words_str}")
        log.info(
            "  Sent host comm_id=0x%016x: %s",
            h["comm_id"], words_str,
        )


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run(port_path: str, baud: int, phyname: str, keys_path: str) -> None:
    log.info("Opening %s at %d baud", port_path, baud)
    with serial.Serial(port_path, baud, timeout=1) as port:
        log.info("Serial port open — waiting for commands from RP2040-Zero")
        buf = b""
        while True:
            chunk = port.read(256)
            if chunk:
                buf += chunk
            while b"\n" in buf:
                line_bytes, buf = buf.split(b"\n", 1)
                line = line_bytes.decode("ascii", errors="replace").strip()
                if not line:
                    continue
                log.debug("RX: %s", line)
                cmd = line.upper()
                if cmd == "SCAN":
                    try:
                        _handle_scan(port, phyname, keys_path)
                    except Exception as e:
                        log.error("Scan error: %s", e, exc_info=True)
                        _send(port, f"ERR {e}")
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
        help="Serial port for the RP2040-Zero UART (default: /dev/ttyAMA0)",
    )
    parser.add_argument(
        "--baud", type=int, default=115200,
        help="Baud rate (default: 115200; match RP2040 UART init)",
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
