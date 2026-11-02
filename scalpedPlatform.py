#!/usr/bin/env python3
# coding:UTF-8

# -------------------------------------------------------------------------------------
#           PYTHON3 SCRIPT FILE FOR THE REMOTE ANALYSIS OF SPACE CRAFT
#         BY TERENCE BROADBENT MSc DIGITAL FORENSICS & CYBERCRIME ANALYSIS
# -------------------------------------------------------------------------------------

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : CORE
# Details : Load required imports.
# Modified: HEX + ASCII output, transcript synchronisation and forensic logging.
# -------------------------------------------------------------------------------------

import argparse
import time
import json
import zlib
import sys
import re
import contextlib

from io import StringIO
from pwn import remote
from pathlib import Path
from datetime import datetime

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : CORE
# Details : Load application variables via JSON configuration or command-line
# Modified: N/A
# -------------------------------------------------------------------------------------

if len(sys.argv) == 2 and sys.argv[1].lstrip().startswith("{"):
    config = json.loads(sys.argv[1])
else:
    parser = argparse.ArgumentParser(description="Spacecraft tracking system")

    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--port2", type=int, required=False)
    parser.add_argument("--spacecraft-id", type=int, required=False)
    parser.add_argument("--virtual-channel-id", type=int, required=False)
    parser.add_argument("--apid", type=int, required=False)
    parser.add_argument("--payload", required=False)
    parser.add_argument("--packet-count", type=int, required=False)
    parser.add_argument("--tc-packet-count", type=int, required=False)
    args = parser.parse_args()
    config = {
        "host": args.host,
        "port": args.port,
        "port2": args.port2,
        "spacecraft_id": args.spacecraft_id,
        "virtual_channel_id": args.virtual_channel_id,
        "apid": args.apid,
        "payload": args.payload,
        "packet_count": args.packet_count,
        "tc_packet_count": args.tc_packet_count,
    }

host = config["host"]
port = config["port"]
port2 = config.get("port2")
spacecraft_id = config.get("spacecraft_id")
virtual_channel_id = config.get("virtual_channel_id")
apid = config.get("apid")
payload = config.get("payload")
packet_count = config.get("packet_count")
tc_packet_count = config.get("tc_packet_count")

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : CORE
# Details : Define application variables
# -------------------------------------------------------------------------------------

connection = None
transcript = []
outdir = Path.cwd()
outdir.mkdir(parents=True, exist_ok=True)
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
transcript_path = outdir / f"uboot_deep_dump_{timestamp}.txt"
underline = "=" * 100

EEPROM_OFFSETS = (
    0x0000,
    0x0400,
    0x0800,
    0x1000,
    0x2000,
    0x4000,
    0x8000,
)

ENV_NAMES = {
    b"arch", b"baudrate", b"board", b"board_name",
    b"bootcmd", b"bootdelay", b"boot_targets", b"cpu",
    b"fdt_addr", b"fdtcontroladdr", b"kernel_addr_r",
    b"loadaddr", b"pxefile_addr_r", b"ramdisk_addr_r",
    b"scriptaddr", b"env_offset", b"vendor",
}

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : CORE
# Details : Output handling and transcript management.
# -------------------------------------------------------------------------------------

def emit(text):
    if not text:
        return
    print(text, end="")
    transcript.append(text)

def clean_console_output(text):
    filtered_lines = []
    for line in text.splitlines():
        if "Bloblist at 0 not found" in line:
            continue
        if "alloc space exhausted" in line:
            continue
        # Remove U-Boot => prompt.
        line = re.sub(r"^\s*=>\s*", "", line)
        filtered_lines.append(line)
    return "\n".join(filtered_lines) + ("\n" if filtered_lines else "")

def remove_hex_dump_lines(text):
    hex_pattern = re.compile(r"^\s*[0-9a-fA-F]{1,8}\s*:\s*" r"(?:[0-9a-fA-F]{2}\s*){1,16}$")
    return "\n".join(line for line in text.splitlines() if not hex_pattern.match(line)) + "\n"

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : CORE
# Details : Create functional subroutines called from main.
# Modified: Remote command handling.
# -------------------------------------------------------------------------------------

def send_cmd(conn, cmd, delay=0.35):
    conn.sendline(cmd.encode())
    time.sleep(delay)
    return conn.recvrepeat(0.35).decode("latin-1",errors="replace")

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : CORE
# Details : Extract U-Boot I2C memory and display HEX + ASCII.
# -------------------------------------------------------------------------------------

def parse_hex_dump(text):
    data = bytearray()
    hex_pattern = re.compile(r"^\s*(?:=>\s*)?" r"([0-9a-fA-F]{1,8})\s*:\s*" r"((?:[0-9a-fA-F]{2}\s*)+)")
    for line in text.splitlines():
        match = hex_pattern.match(line)
        if not match:
            continue
        address = int(match.group(1), 16)
        hex_bytes = match.group(2).split()
        chunk = bytes(int(byte, 16) for byte in hex_bytes)
        data.extend(chunk)
        ascii_text = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
        hex_text = " ".join(f"{byte:02x}" for byte in chunk)
        print(f"{address:04x}: " f"{hex_text:<47} " f"|{ascii_text}|")
    return bytes(data)

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : CORE
# Details : Perform forensic analysis of EEPROM and I2C data.
# -------------------------------------------------------------------------------------

def analyse(bus, chip, offset, text):
    data = parse_hex_dump(text)
    print(f"\n{'=' * 72}")
    print(f"ANALYSIS  bus={bus}  device=0x{chip:02x} " f"offset=0x{offset:04x}")
    print(f"{'=' * 72}")
    if not data:
        print("[!] No bytes parsed.")
        return
    if all(b == 0x00 for b in data):
        print("[+] Entire block is 0x00.")
    elif all(b == 0xff for b in data):
        print("[+] Entire block is 0xff (likely erased/unprogrammed).")
    else:
        print(f"[+] Parsed {len(data)} bytes.")
    strings = []
    for m in re.finditer(rb"[\x20-\x7e]{4,}", data):
        strings.append((offset + m.start(), m.group().decode("ascii", "replace")))
    if strings:
        print("\n[ASCII STRINGS]")
        for addr, value in strings:
            print(f"  0x{addr:04x}: {value}")
    nul_strings = []
    for part in data.split(b"\x00"):
        if len(part) >= 4 and all(32 <= b <= 126 for b in part):
            nul_strings.append(part.decode("ascii", "replace"))
    if nul_strings:
        print("\n[NUL-SEPARATED STRINGS]")
        for value in nul_strings:
            print(f"  {value}")

    # Possible U-Boot environment variables.

    env_hits = []
    for part in data.split(b"\x00"):
        if b"=" not in part:
            continue
        name, value = part.split(b"=", 1)
        if name in ENV_NAMES:
            env_hits.append((name.decode("ascii", "replace"),value.decode("latin-1", "replace")))
    if env_hits:
        print("\n[POSSIBLE U-BOOT ENVIRONMENT]")
        for name, value in env_hits:
            print(f"  {name}={value}")

    # Useful challenge keywords.

    keywords = (
        b"ciphertext", b"secret", b"password", b"token",
        b"payload", b"mission", b"satellite", b"spacecraft",
        b"recovery", b"aes", b"key", b"iv",
    )
    lower = data.lower()
    keyword_hits = []
    for keyword in keywords:
        start = 0
        while True:
            pos = lower.find(keyword, start)
            if pos < 0:
                break
            keyword_hits.append((offset + pos,keyword.decode("ascii")))
            start = pos + len(keyword)
    if keyword_hits:
        print("\n[INTERESTING KEYWORDS]")
        for addr, keyword in keyword_hits:
            print(f"  0x{addr:04x}: {keyword}")

    # CRC32 heuristic.
    # Legacy U-Boot environment CRC may cover the bytes
    # following the first four bytes.

    if len(data) >= 8:
        stored_be = int.from_bytes(data[:4], "big")
        stored_le = int.from_bytes(data[:4], "little")
        calculated = zlib.crc32(data[4:]) & 0xffffffff
        print("\n[CRC32 CHECK]")
        print(f"  first four bytes : {data[:4].hex()}")
        print(f"  stored BE        : 0x{stored_be:08x}")
        print(f"  stored LE        : 0x{stored_le:08x}")
        print(f"  calculated       : 0x{calculated:08x}")
        if calculated in (stored_be, stored_le):
            print("  [!!!] DIRECT CRC32 MATCH - " "investigate this block as environment data.")

    # Compact raw preview for useful blocks.

    if not all(b == 0 for b in data) and not all(b == 0xff for b in data):
        print("\n[RAW PREVIEW - FIRST 128 BYTES]")
        for i in range(0, min(128, len(data)), 16):
            chunk = data[i:i + 16]
            hx = " ".join(f"{b:02x}" for b in chunk)
            asc = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            print(f"  {offset + i:08x}  " f"{hx:<47}  |{asc}|")

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : CORE
# Details : Display application headers.
# Modified: N/A
# -------------------------------------------------------------------------------------

def print_header(title):
    return ("╔" + "═" * 98 + "╗\n" 
        f"║ {title:^96} ║\n"
        "╚" + "═" * 98 + "╝\n\n"
    )

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : CORE
# Details : Record command output and forensic analysis.
# -------------------------------------------------------------------------------------

def record(cmd, output, parse=None):
    cleaned_output = clean_console_output(output)
    result = [f"\n>>> {cmd}\n"]
    if parse is not None:
        display_output = remove_hex_dump_lines(cleaned_output)
    else:
        display_output = cleaned_output
    if display_output.strip():
        result.append(display_output)

    # Capture all analysis output, including HEX + ASCII.
    if parse is not None:
        bus, chip, offset = parse
        analysis_buffer = StringIO()
        with contextlib.redirect_stdout(analysis_buffer):
            analyse(bus,chip,offset,cleaned_output)
        result.append(analysis_buffer.getvalue())

    # Display and save identical output.
    emit("".join(result))

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : CORE
# Details : Perform remote EEPROM and I2C analysis.
# -------------------------------------------------------------------------------------

def eeprom_dump():
    global connection
    transcript.clear()
    emit(print_header("EEPROM DUMPER"))
    try:
        connection = remote(host, port)
        initial = connection.recvrepeat(1.5).decode("latin-1",errors="replace")
        cleaned_initial = clean_console_output(initial)
        emit(cleaned_initial)
        for cmd in ("version", "i2c bus", "i2c probe", "printenv"):
            record(cmd,send_cmd(connection, cmd))
        for bus in (0, 1):
            emit("\n" + "#" * 100 + "\n" f"# I2C BUS {bus}\n" + "#" * 100 + "\n")
            cmd = f"i2c dev {bus}"
            record(cmd,send_cmd(connection, cmd))
            for offset in EEPROM_OFFSETS:
                cmd = f"i2c md 50 {offset:x} {0x0400:x}"
                output = send_cmd(connection,cmd,delay=0.5)
                record(cmd,output,parse=(bus, 0x50, offset))
            for chip in (0x18, 0x68):
                cmd = f"i2c md {chip:x} 0 40"
                output = send_cmd(connection, cmd)
                record(cmd,output,parse=(bus, chip, 0))
        cmd = "printenv env_offset"
        record(cmd,send_cmd(connection, cmd))
    except KeyboardInterrupt:
        emit("\n[!] Interrupted.\n")
    except Exception as exc:
        emit(f"\n[!] Error: {exc}\n")
    finally:
        if connection:
            try:
                connection.close()
            except Exception:
                pass
            connection = None
        transcript_path.write_text("".join(transcript),encoding="latin-1",errors="replace")
        emit("\n" + underline + "\n")
        emit("DONE\n")
        emit(underline + "\n")
        emit(f"Transcript: {transcript_path}\n")

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : CORE
# Details : Main application entry point.
# Modified: N/A
# -------------------------------------------------------------------------------------

if __name__ == "__main__":
    eeprom_dump()