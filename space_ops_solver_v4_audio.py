#!/usr/bin/env python3
"""HTB Space Ops - real-audio AFSK1200 diagnostic client.

Evidence-backed settings:
  SCID=42, APID=26, VCID=6
  App sequence: 0x00:BEGIN, then GETFLAG using the ACK's returned counter
  ZMQ client sockets: TX PUSH, RX PULL (both ZMTP handshakes observed)
  Test format: mono float32 AFSK audio at 48 ksample/s.

Why complex IQ: the supplied flag.wav is 48 kHz, 16-bit stereo. Its two
channels are quadrature components (I/Q): sqrt(I^2+Q^2) is approximately
constant and complex phase increments switch between 1200 and 2200 Hz.
That is a much stronger match for a raw SDR modem than a single real
float32 audio channel. The modem's exact byte contract is still not published,
so --tx-format and --rx-format remain configurable.

Only use against the authorized HTB challenge instance. The script sends
BEGIN once and only sends GETFLAG after finding an ACK. It does not retry.
"""

from __future__ import annotations

import argparse
import io
import re
import struct
import sys
import time
import wave
from pathlib import Path
from typing import Iterable

import numpy as np

try:
    import zmq
except ImportError:
    zmq = None

HOST_DEFAULT = "154.57.164.83"
TX_PORT_DEFAULT = 32380
RX_PORT_DEFAULT = 30545
SCID = 42
VCID = 6
APID = 26
BAUD = 1200
MARK_HZ = 1200       # bit 1
SPACE_HZ = 2200      # bit 0
SAMPLE_RATE_DEFAULT = 48_000


def crc16_ccitt_false(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def make_space_packet(apid: int, packet_count: int, payload: bytes) -> bytes:
    if not 0 <= apid <= 0x7FF:
        raise ValueError("APID must be in 0..2047")
    if not 0 <= packet_count <= 0x3FFF:
        raise ValueError("packet count must be in 0..16383")
    if not payload:
        raise ValueError("Space Packet payload must not be empty")
    packet_id = (1 << 12) | apid  # version=0, TC packet, no secondary header
    sequence_control = (0b11 << 14) | packet_count
    return struct.pack(">HHH", packet_id, sequence_control, len(payload) - 1) + payload


def make_tc_frame(packet: bytes, tc_count: int, bypass: int = 0) -> bytes:
    if bypass not in (0, 1):
        raise ValueError("bypass must be 0 or 1")
    if not 0 <= tc_count <= 0xFF:
        raise ValueError("TC frame counter must be in 0..255")
    first_word = (bypass << 13) | SCID
    total_length = 5 + len(packet) + 2
    if total_length - 1 > 0x3FF:
        raise ValueError("TC frame exceeds its 10-bit length field")
    second_word = (VCID << 10) | (total_length - 1)
    header_and_packet = struct.pack(">HHB", first_word, second_word, tc_count) + packet
    return header_and_packet + struct.pack(">H", crc16_ccitt_false(header_and_packet))


def make_command_frame(app_counter: int, command: str, tc_count: int,
                       packet_count: int, bypass: int) -> bytes:
    if not 0 <= app_counter <= 0xFF:
        raise ValueError("application counter must be in 0..255")
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", command):
        raise ValueError("invalid command")
    app_payload = f"0x{app_counter:02x}:{command}".encode("ascii")
    packet = make_space_packet(APID, packet_count, app_payload)
    return make_tc_frame(packet, tc_count, bypass)


def bytes_to_bits(data: bytes) -> Iterable[int]:
    for octet in data:
        for shift in range(7, -1, -1):
            yield (octet >> shift) & 1


def afsk1200_iq(data: bytes, sample_rate: int, amplitude: float) -> np.ndarray:
    """Generate continuous-phase complex baseband IQ; 1200 Hz=1, 2200 Hz=0."""
    if sample_rate % BAUD:
        raise ValueError("sample rate must be an integer multiple of 1200")
    if not 0 < amplitude <= 1:
        raise ValueError("amplitude must be in (0, 1]")
    sps = sample_rate // BAUD
    n = np.arange(sps, dtype=np.float64)
    iq = np.empty(len(data) * 8 * sps, dtype=np.complex64)
    phase = 0.0
    cursor = 0
    for bit in bytes_to_bits(data):
        frequency = MARK_HZ if bit else SPACE_HZ
        omega = 2.0 * np.pi * frequency / sample_rate
        block = amplitude * np.exp(1j * (phase + omega * n))
        iq[cursor:cursor + sps] = block.astype(np.complex64)
        phase = (phase + omega * sps) % (2.0 * np.pi)
        cursor += sps
    return iq


def iq_to_bits(iq: np.ndarray, sample_rate: int) -> list[bytes]:
    """Recover candidate byte streams from complex IQ with sample/byte alignment search."""
    if sample_rate % BAUD:
        raise ValueError("sample rate must be an integer multiple of 1200")
    sps = sample_rate // BAUD
    z = np.asarray(iq, dtype=np.complex128).reshape(-1)
    if z.size < sps * 8 + 1:
        return []
    # Phase increment of I+jQ gives instantaneous baseband frequency.
    increments = np.angle(z[1:] * np.conjugate(z[:-1]))
    inst_freq = increments * sample_rate / (2.0 * np.pi)
    # One phase difference is unavailable at the final sample; extend the final
    # observed instantaneous-frequency estimate across that last sample so an
    # otherwise complete final symbol is retained.
    if inst_freq.size:
        inst_freq = np.concatenate((inst_freq, inst_freq[-1:]))
    candidates: list[bytes] = []
    seen: set[bytes] = set()
    weights = (1 << np.arange(7, -1, -1, dtype=np.uint16))
    for sample_offset in range(sps):
        count = (len(inst_freq) - sample_offset) // sps
        if count < 8:
            continue
        freq_blocks = inst_freq[sample_offset:sample_offset + count * sps].reshape(count, sps)
        # Median is robust to transitions and a small number of noisy samples.
        symbol_freq = np.median(freq_blocks, axis=1)
        bits = (symbol_freq < 1700.0).astype(np.uint8)  # 1200 Hz=1, 2200 Hz=0
        for bit_offset in range(8):
            aligned = bits[bit_offset:]
            nbytes = len(aligned) // 8
            if not nbytes:
                continue
            octets = aligned[:nbytes * 8].reshape(nbytes, 8)
            candidate = np.sum(octets * weights, axis=1).astype(np.uint8).tobytes()
            if candidate not in seen:
                seen.add(candidate)
                candidates.append(candidate)
    return candidates


def write_iq_wav(path: str, iq: np.ndarray, sample_rate: int) -> None:
    """Write standard stereo PCM WAV with I in left, Q in right."""
    stereo = np.empty((len(iq), 2), dtype="<i2")
    stereo[:, 0] = (np.clip(iq.real, -1, 1) * 32767).astype("<i2")
    stereo[:, 1] = (np.clip(iq.imag, -1, 1) * 32767).astype("<i2")
    with wave.open(path, "wb") as wf:
        wf.setnchannels(2)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        wf.writeframes(stereo.tobytes())


def read_iq_wav(path: str) -> tuple[np.ndarray, int]:
    with wave.open(path, "rb") as wf:
        rate, channels, width = wf.getframerate(), wf.getnchannels(), wf.getsampwidth()
        raw = wf.readframes(wf.getnframes())
    if channels != 2 or width != 2:
        raise ValueError("Expected 16-bit stereo I/Q WAV (I=left, Q=right)")
    data = np.frombuffer(raw, dtype="<i2").reshape(-1, 2).astype(np.float32) / 32768.0
    return (data[:, 0] + 1j * data[:, 1]).astype(np.complex64), rate


def tx_payload(iq: np.ndarray, fmt: str) -> bytes:
    if fmt == "complex64":
        # NumPy complex64 layout is interleaved little-endian float32 I,Q.
        return np.asarray(iq, dtype="<c8").tobytes()
    if fmt == "iq-int16":
        out = np.empty((len(iq), 2), dtype="<i2")
        out[:, 0] = (np.clip(iq.real, -1, 1) * 32767).astype("<i2")
        out[:, 1] = (np.clip(iq.imag, -1, 1) * 32767).astype("<i2")
        return out.tobytes()
    if fmt == "real-float32":
        return np.asarray(iq.real, dtype="<f4").tobytes()
    raise ValueError(f"unsupported TX format: {fmt}")


def decode_rx_iq(raw: bytes, fmt: str, sample_rate: int) -> tuple[np.ndarray, int]:
    if fmt == "wav-iq" or raw.startswith(b"RIFF"):
        buf = io.BytesIO(raw)
        with wave.open(buf, "rb") as wf:
            rate, channels, width = wf.getframerate(), wf.getnchannels(), wf.getsampwidth()
            b = wf.readframes(wf.getnframes())
        if channels != 2 or width != 2:
            raise ValueError("RX WAV must be 16-bit stereo I/Q")
        d = np.frombuffer(b, dtype="<i2").reshape(-1, 2).astype(np.float32) / 32768.0
        return (d[:, 0] + 1j * d[:, 1]).astype(np.complex64), rate
    if fmt == "iq-int16":
        if len(raw) % 4:
            raise ValueError("IQ int16 payload length must be divisible by 4")
        d = np.frombuffer(raw, dtype="<i2").reshape(-1, 2).astype(np.float32) / 32768.0
        return (d[:, 0] + 1j * d[:, 1]).astype(np.complex64), sample_rate
    if fmt == "real-float32":
        if len(raw) % 4:
            raise ValueError("float32 payload length must be divisible by 4")
        # The RX stream is real AFSK audio. Convert it to its analytic signal
        # so iq_to_bits() can use phase increments exactly as for complex IQ.
        audio = np.frombuffer(raw, dtype="<f4").astype(np.float64)
        n = len(audio)
        if n == 0:
            return np.empty(0, dtype=np.complex64), sample_rate
        spectrum = np.fft.fft(audio)
        h = np.zeros(n, dtype=np.float64)
        h[0] = 1.0
        if n % 2 == 0:
            h[1:n // 2] = 2.0
            h[n // 2] = 1.0
        else:
            h[1:(n + 1) // 2] = 2.0
        analytic = np.fft.ifft(spectrum * h)
        return analytic.astype(np.complex64), sample_rate
    if len(raw) % 8:
        raise ValueError(f"complex64 payload length {len(raw)} not divisible by 8")
    return np.frombuffer(raw, dtype="<c8").copy(), sample_rate


def extract_application(data: bytes) -> list[tuple[int, bytes]]:
    fields = []
    for m in re.finditer(rb"0x([0-9a-fA-F]{2}):([^\x00\r\n]*)", data):
        fields.append((int(m.group(1), 16), m.group(2).strip(b" \t\x00\xff")))
    return fields


def extract_flag(data: bytes) -> str | None:
    m = re.search(rb"HTB\{[^}\r\n]+\}", data)
    return m.group().decode("ascii", errors="replace") if m else None


def printable(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def recv_burst(sock, timeout: float, quiet: float, part_index: int = -1) -> bytes:
    poller = zmq.Poller()
    poller.register(sock, zmq.POLLIN)
    deadline = time.monotonic() + timeout
    last_message = None
    chunks: list[bytes] = []
    while time.monotonic() < deadline:
        wait_ms = max(1, min(250, int((deadline - time.monotonic()) * 1000)))
        events = dict(poller.poll(wait_ms))
        if sock in events and events[sock] & zmq.POLLIN:
            parts = sock.recv_multipart()
            if not parts:
                continue
            try:
                chunks.append(parts[part_index])
            except IndexError as exc:
                raise ValueError(f"RX message has {len(parts)} parts; --rx-part={part_index} is invalid") from exc
            last_message = time.monotonic()
        elif last_message is not None and time.monotonic() - last_message >= quiet:
            break
    if not chunks:
        raise TimeoutError("No data arrived on RX PULL")
    return b"".join(chunks)


def live(args) -> None:
    if zmq is None:
        raise RuntimeError("Install pyzmq: python3 -m pip install pyzmq")
    context = zmq.Context()
    tx = context.socket(zmq.PUSH)
    rx = context.socket(zmq.PULL)
    for s in (tx, rx):
        s.setsockopt(zmq.LINGER, 0)
    tx.setsockopt(zmq.IMMEDIATE, 1)
    tx_ep = f"tcp://{args.host}:{args.tx_port}"
    rx_ep = f"tcp://{args.host}:{args.rx_port}"
    tx.connect(tx_ep)
    rx.connect(rx_ep)
    print(f"[*] TX PUSH -> {tx_ep}")
    print(f"[*] RX PULL <- {rx_ep}")
    print(f"[*] TX sample format: {args.tx_format}; RX sample format: {args.rx_format}")
    try:
        print(f"[*] Waiting {args.startup_delay:.1f}s for ZMQ setup")
        time.sleep(args.startup_delay)
        if not tx.poll(int(args.connect_timeout * 1000), zmq.POLLOUT):
            raise TimeoutError("TX PUSH is not writable")

        def send_one(app_counter: int, command: str, tc_count: int, packet_count: int) -> list[bytes]:
            frame = make_command_frame(app_counter, command, tc_count, packet_count, args.bypass)
            iq = afsk1200_iq(frame, args.sample_rate, args.amplitude)
            payload = tx_payload(iq, args.tx_format)
            print(f"\n[+] {command} application payload: 0x{app_counter:02x}:{command}")
            print(f"[+] TC frame ({len(frame)} bytes): {frame.hex()}")
            print(f"[+] FECF: 0x{int.from_bytes(frame[-2:], 'big'):04x}")
            print(f"[+] Modulation: {len(iq)} symbols samples at {args.sample_rate} sps; TX={args.tx_format}, {len(payload)} bytes")
            tx.send(payload)
            raw = recv_burst(rx, args.rx_timeout, args.quiet, args.rx_part)
            iq_rx, rate = decode_rx_iq(raw, args.rx_format, args.sample_rate)
            print(f"[+] RX: {len(iq_rx)} complex samples, {rate} sps, {len(raw)} bytes")
            if args.save_rx:
                path = args.save_rx.replace("{command}", command.lower())
                write_iq_wav(path, iq_rx, rate)
                print(f"[+] Saved stereo I/Q WAV: {path}")
            candidates = iq_to_bits(iq_rx, rate)
            return candidates

        # Send BEGIN once. Do not retry automatically: application state is stateful.
        begin_candidates = send_one(0, "BEGIN", args.tc_count, args.packet_count)
        ack = None
        for candidate in begin_candidates:
            for counter, body in extract_application(candidate):
                if b"ACK" in body.upper():
                    ack = (counter, body, candidate)
                    break
            if ack:
                break
        if not ack:
            print("[-] No recognisable ACK field. Decoded candidate streams:")
            for candidate in begin_candidates[:12]:
                print("    HEX", candidate[:160].hex())
                print("    TXT", repr(printable(candidate[:160])))
            raise RuntimeError("BEGIN response did not contain an ACK")

        next_app_counter, ack_body, _ = ack
        print(f"[+] ACK body={ack_body!r}; next application counter=0x{next_app_counter:02x}")
        next_tc_count = (args.tc_count + 1) & 0xFF
        next_packet_count = (args.packet_count + 1) & 0x3FFF
        flag_candidates = send_one(next_app_counter, "GETFLAG", next_tc_count, next_packet_count)
        for candidate in flag_candidates:
            flag = extract_flag(candidate)
            if flag:
                print(f"\n[+] FLAG: {flag}")
                return
        print("[-] Received telemetry but no HTB{...} string was decoded:")
        for candidate in flag_candidates[:12]:
            print("    HEX", candidate[:200].hex())
            print("    TXT", repr(printable(candidate[:200])))
        raise RuntimeError("No flag found in GETFLAG telemetry")
    finally:
        tx.close(0)
        rx.close(0)
        context.term()


def self_test() -> None:
    assert crc16_ccitt_false(b"123456789") == 0x29B1
    frame = make_command_frame(0, "BEGIN", 0, 0, 0)
    assert frame.hex() == "002a181600101ac0000009307830303a424547494efcf3"
    assert crc16_ccitt_false(frame[:-2]) == int.from_bytes(frame[-2:], "big")
    test = b"HTB{IQ_roundtrip_1200_2200}"
    iq = afsk1200_iq(test, SAMPLE_RATE_DEFAULT, 0.8)
    candidates = iq_to_bits(iq, SAMPLE_RATE_DEFAULT)
    assert any(test in c for c in candidates), "complex IQ modulation/demodulation failed"
    audio = iq.real.astype("<f4")
    n = len(audio)
    spectrum = np.fft.fft(audio.astype(np.float64))
    h = np.zeros(n, dtype=np.float64)
    h[0] = 1.0
    if n % 2 == 0:
        h[1:n // 2] = 2.0
        h[n // 2] = 1.0
    else:
        h[1:(n + 1) // 2] = 2.0
    analytic = np.fft.ifft(spectrum * h).astype(np.complex64)
    audio_candidates = iq_to_bits(analytic, SAMPLE_RATE_DEFAULT)
    assert any(test in c for c in audio_candidates), "real-audio modulation/demodulation failed"
    print("[+] Self-test passed")
    print(f"[+] BEGIN frame (bypass=0): {frame.hex()}")
    print(f"[+] FECF: 0x{int.from_bytes(frame[-2:], 'big'):04x}")
    print(f"[+] IQ samples: {len(iq)}; bytes as complex64: {iq.nbytes}")
    print("[+] Complex IQ and real-audio AFSK1200 round-trips passed")


def main() -> int:
    p = argparse.ArgumentParser(description="HTB Space Ops real-audio AFSK1200 diagnostic client")
    p.add_argument("--host", default=HOST_DEFAULT)
    p.add_argument("--tx-port", type=int, default=TX_PORT_DEFAULT)
    p.add_argument("--rx-port", type=int, default=RX_PORT_DEFAULT)
    p.add_argument("--sample-rate", type=int, default=SAMPLE_RATE_DEFAULT)
    p.add_argument("--amplitude", type=float, default=0.8)
    p.add_argument("--bypass", type=int, choices=(0, 1), default=0)
    p.add_argument("--tc-count", type=int, default=0)
    p.add_argument("--packet-count", type=int, default=0)
    p.add_argument("--tx-format", choices=("complex64", "iq-int16", "real-float32"), default="real-float32")
    p.add_argument("--rx-format", choices=("complex64", "iq-int16", "wav-iq", "real-float32"), default="real-float32")
    p.add_argument("--rx-part", type=int, default=-1, help="multipart item holding sample bytes; default last")
    p.add_argument("--startup-delay", type=float, default=2.0)
    p.add_argument("--connect-timeout", type=float, default=5.0)
    p.add_argument("--rx-timeout", type=float, default=12.0)
    p.add_argument("--quiet", type=float, default=0.75)
    p.add_argument("--save-rx", help='save RX as stereo I/Q WAV; supports {command}')
    p.add_argument("--write-begin-iq", metavar="PATH", help="write BEGIN as stereo I/Q WAV; no transmission")
    p.add_argument("--decode-iq-wav", metavar="PATH", help="decode stereo I/Q WAV and print candidates")
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--live", action="store_true")
    args = p.parse_args()
    if args.self_test:
        self_test()
        return 0
    if args.write_begin_iq:
        frame = make_command_frame(0, "BEGIN", args.tc_count, args.packet_count, args.bypass)
        iq = afsk1200_iq(frame, args.sample_rate, args.amplitude)
        write_iq_wav(args.write_begin_iq, iq, args.sample_rate)
        print(f"[+] Wrote stereo I/Q WAV: {args.write_begin_iq}")
        print(f"[+] Frame {frame.hex()} ; IQ samples={len(iq)} ; raw complex64 bytes={iq.nbytes}")
        return 0
    if args.decode_iq_wav:
        iq, rate = read_iq_wav(args.decode_iq_wav)
        print(f"[+] Loaded {len(iq)} IQ samples at {rate} sps")
        print(f"[+] Magnitude mean={np.abs(iq).mean():.5f}, std={np.abs(iq).std():.5f}")
        candidates = iq_to_bits(iq, rate)
        for c in candidates[:20]:
            print("HEX", c[:180].hex())
            print("TXT", repr(printable(c[:180])))
            flag = extract_flag(c)
            if flag:
                print("[+] FLAG", flag)
        return 0
    if args.live:
        live(args)
        return 0
    frame = make_command_frame(0, "BEGIN", args.tc_count, args.packet_count, args.bypass)
    iq = afsk1200_iq(frame, args.sample_rate, args.amplitude)
    print("[+] Dry-run only")
    print("[+] Frame:", frame.hex())
    print(f"[+] FECF: 0x{int.from_bytes(frame[-2:], 'big'):04x}")
    print(f"[+] Complex IQ: {len(iq)} samples, {iq.nbytes} bytes at {args.sample_rate} sps")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted", file=sys.stderr)
        raise SystemExit(130)
    except Exception as exc:
        print(f"[-] {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)
