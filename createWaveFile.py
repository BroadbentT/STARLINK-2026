#!/usr/bin/env python3
# coding:UTF-8

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Load required imports.
# Modified: N/A
# -------------------------------------------------------------------------------------

import argparse
import json
import math
import struct
import sys
import wave

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
    parser = argparse.ArgumentParser(description="Payload to AFSK1200 WAV encoder")
    parser.add_argument("--host", required=False)
    parser.add_argument("--port", type=int, required=False)
    parser.add_argument("--port2", type=int, required=False)
    parser.add_argument("--spacecraft-id", type=int, required=False)
    parser.add_argument("--virtual-channel-id", type=int, required=False)
    parser.add_argument("--apid", type=int, required=False)
    parser.add_argument("--payload", required=True)
    parser.add_argument("--packet-count", type=int, required=False)
    parser.add_argument("--tc-packet-count", type=int, required=False)
    parser.add_argument("--output", default="encoded.wav")
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
        "output": args.output,
    }

host = config.get("host")
port = config.get("port")
port2 = config.get("port2")
spacecraft_id = config.get("spacecraft_id")
virtual_channel_id = config.get("virtual_channel_id")
apid = config.get("apid")
user_payload = config["payload"].encode("utf-8")
packet_count = config.get("packet_count")
tc_packet_count = config.get("tc_packet_count")
output_path = config.get("output", "encoded.wav")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Create functional subroutines called from main.
# Modified: N/A
# Convert the supplied payload bytes directly into AFSK1200 PCM samples.
# Bit mapping matches the supplied spaceops.py:
# bit 1 = 1200 Hz
# bit 0 = 2200 Hz
# This directly modulates the payload bytes. It does not add a Space Packet,
# TC Transfer Frame, FECF, preamble, NRZI, HDLC flags, or bit stuffing.

# -------------------------------------------------------------------------------------


def bytes_to_bits_msb(data: bytes):
    """Yield each byte's bits, most-significant bit first."""
    for value in data:
        for shift in range(7, -1, -1):
            yield (value >> shift) & 1

def modulate_afsk1200_pcm(data: bytes,sample_rate: int = 48_000,baud: int = 1200,mark_hz: float = 1200.0,space_hz: float = 2200.0,amplitude: float = 0.75,):
    if sample_rate <= 0 or baud <= 0 or sample_rate % baud:
        raise ValueError("sample_rate must be a positive integer multiple of baud")
    if not 0.0 < amplitude <= 1.0:
        raise ValueError("amplitude must be in (0, 1]")
    samples_per_bit = sample_rate // baud
    phase = 0.0
    scale = 32767.0 * amplitude
    output = bytearray()
    for bit in bytes_to_bits_msb(data):
        frequency = mark_hz if bit else space_hz
        phase_step = (2.0 * math.pi * frequency) / sample_rate
        for _ in range(samples_per_bit):
            sample = int(round(math.sin(phase) * scale))
            output.extend(struct.pack("<h", sample))
            phase = (phase + phase_step) % (2.0 * math.pi)
    sample = int(round(math.sin(phase) * scale))
    output.extend(struct.pack("<h", sample))
    return bytes(output)

def write_afsk1200_wav(data: bytes, output_path: str) -> None:
    pcm = modulate_afsk1200_pcm(data)
    with wave.open(output_path, "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(48_000)
        wav.writeframes(pcm)

def waveCreator():
    if not user_payload:
        raise ValueError("Payload cannot be empty")
    write_afsk1200_wav(user_payload, output_path)
    print(f"Payload bytes : {user_payload!r}")
    print(f"Payload hex   : {user_payload.hex(' ')}")
    print(f"WAV file      : {output_path}")
    print("Format        : 48 kHz, 16-bit, mono AFSK1200")
    print("No packet/frame headers or network transmission added.")
    return 0

if __name__ == "__main__":
    waveCreator()
