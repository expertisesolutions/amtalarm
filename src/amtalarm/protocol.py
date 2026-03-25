"""Frame encode/decode, BCD utils, command builders, and packet parsers for IsecNet V1."""

import time
from datetime import datetime

import crcengine

from .models import (
    ContactIDEvent,
    DeviceInfo,
    GeneralStatus,
    PanelStatus,
    ProblemStatus,
    SMART_MODEL_CODES,
)
from .events import (
    AMT_EVENT_MESSAGES,
)

# CRC-16 engine for ISECProgram
_crc_isecprogram = crcengine.create(0x8005, 16, 0, False, False, "", 0)


# --- BCD utilities ---

def bcd_to_decimal(mbytes: bytes, unescape_zeros=True) -> int:
    """Convert a sequence of BCD-encoded nibbles to integer."""
    def unescape_zero(i: int):
        return i if i != 0xA else 0

    if unescape_zeros:
        mbytes = bytes(unescape_zero(b) for b in mbytes)

    return sum(10 ** (len(mbytes) - i - 1) * b for i, b in enumerate(mbytes))


def decimal_to_bcd_nibble(decimal: int) -> int:
    """Convert a decimal 0-99 into two BCD nibbles packed in one byte."""
    if decimal < 0 or decimal > 99:
        raise ValueError("argument must be between 0 and 99")
    return (decimal // 10) << 4 | (decimal % 10)


def code_to_bcd(code: str) -> bytes:
    """Convert a password code string into BCD bytes."""
    result = bytes()
    if len(code) % 2:
        code = "0" + code
    for i in range(len(code) // 2):
        ch = (ord(code[i * 2]) - ord('0')) * 10
        cl = ord(code[i * 2 + 1]) - ord('0')
        result += bytes([decimal_to_bcd_nibble(ch + cl)])
    return result


# --- Checksum ---

def xor_checksum(data: bytes) -> int:
    """Compute XOR checksum (inverted) for IsecNet V1 frame."""
    res = 0
    for c in data:
        res ^= c
    return (res ^ 0xFF) & 0xFF


# --- Frame encoding ---

def encode_v1_frame(packet: bytes) -> bytes:
    """Encode a packet into an IsecNet V1 frame with length byte and checksum."""
    buf = bytes([len(packet)]) + packet
    crc = xor_checksum(buf + bytes([0]))
    return buf + bytes([crc])


def encode_isecprogram_frame(packet: bytes) -> bytes:
    """Encode an ISECProgram packet wrapped in IsecNet V1 frame."""
    crc16 = _crc_isecprogram(bytes([len(packet)]) + packet)
    buf = b"\xe7" + bytes([len(packet)]) + packet + bytes([crc16 >> 8, crc16 & 0xFF])
    return encode_v1_frame(buf)


# --- Command builders ---

def build_request_model() -> bytes:
    """Build model request packet."""
    return bytes([0xC2])


def build_request_zones(password: str) -> bytes:
    """Build zone status request (ISECMobile 0x5B)."""
    return b"\xe9\x21" + password.encode("utf-8") + b"\x5b\x21"


def build_arm(password: str) -> bytes:
    """Build arm all partitions packet."""
    return b"\xe9\x21" + password.encode("utf-8") + b"\x41\x21"


def build_arm_partition(partition: int, password: str) -> bytes:
    """Build arm specific partition packet."""
    return b"\xe9\x21" + password.encode("utf-8") + b"\x41" + bytes([0x40 + partition + 1]) + b"\x21"


def build_disarm(password: str) -> bytes:
    """Build disarm all partitions packet."""
    return b"\xe9\x21" + password.encode("utf-8") + b"\x44\x21"


def build_disarm_partition(partition: int, password: str) -> bytes:
    """Build disarm specific partition packet."""
    return b"\xe9\x21" + password.encode("utf-8") + b"\x44" + bytes([0x40 + partition + 1]) + b"\x21"


def build_trigger(password: str, panic_type: int) -> bytes:
    """Build panic trigger packet."""
    return b"\xe9\x21" + password.encode("utf-8") + bytes([0x45, panic_type]) + b"\x21"


def build_bypass(zones: list[int], password: str) -> bytes:
    """Build bypass zones packet."""
    state = bytearray(b'\x00' * 8)
    for i in range(8):
        for j in range(8):
            if (i * 8 + j) in zones:
                state[i] |= 1 << j
    return b"\xe9\x21" + password.encode("utf-8") + bytes([0x42]) + bytes(state) + b"\x21"


def build_datetime_response(cmd: int, timezone_offset: int) -> bytes:
    """Build datetime response packet for panel's 0x80 request."""
    now = time.time()
    (tm_year, tm_mon, tm_mday, tm_hour, tm_min, tm_sec, tm_wday, _, _) = time.gmtime(
        now + timezone_offset * 3600
    )
    tm_year -= 2000
    tm_wday = (tm_wday + 1) % 7 + 1
    return bytes([cmd]) + bytes(
        map(decimal_to_bcd_nibble, [tm_year, tm_mon, tm_mday, tm_wday, tm_hour, tm_min, tm_sec])
    )


def build_isecprogram_auth(password: str) -> bytes:
    """Build ISECProgram authentication packet (0x11)."""
    return b"\x11" + code_to_bcd(password) + b"\x99"


def build_isecprogram_close() -> bytes:
    """Build ISECProgram close session packet (0x15)."""
    return b"\x15"


def build_isecprogram_general_status_smart() -> bytes:
    """Build ISECProgram extended status request for Smart models (0x27)."""
    return b"\x27"


def build_isecprogram_general_status_legacy() -> bytes:
    """Build ISECProgram general status request for non-Smart models (0x17)."""
    return b"\x17"


def build_isecprogram_problem_status_smart() -> bytes:
    """Build ISECProgram problem status request for Smart models (0x34)."""
    return b"\x34"


def build_isecprogram_problem_status_legacy() -> bytes:
    """Build ISECProgram problem status request for non-Smart models (0x14)."""
    return b"\x14"


# --- Packet parsers ---

def parse_model_response(packet: bytes) -> str:
    """Parse model response (0xC2). Returns model name string."""
    return packet[1:].decode("utf-8")


def parse_mac_response(packet: bytes) -> bytes:
    """Parse MAC response (0xC4). Returns 6-byte MAC."""
    return packet[1:7]


def parse_connect(packet: bytes) -> bytes:
    """Parse connect packet (0x94). Returns partial MAC (3 bytes)."""
    return packet[4:7]


def parse_connect_complementary(packet: bytes) -> DeviceInfo:
    """Parse connect+complementary packet (0x95). Returns DeviceInfo."""
    info = DeviceInfo()
    if len(packet) >= 10:
        info.mac_address = packet[4:10]
    if len(packet) >= 11:
        info.model_code = packet[10]
    if len(packet) >= 14:
        info.firmware_version = f"{packet[11]}.{packet[12]}.{packet[13]}"
    return info


def parse_contact_id(packet: bytes) -> ContactIDEvent | None:
    """Parse Contact ID event (0xB0). Returns ContactIDEvent or None."""
    if len(packet) != 17 or packet[1] not in (0x11, 0x12):
        return None
    client_id = bcd_to_decimal(packet[2:6])
    ev_id = bcd_to_decimal(packet[8:12])
    partition = bcd_to_decimal(packet[12:14]) - 1
    zone = bcd_to_decimal(packet[14:17])
    message = AMT_EVENT_MESSAGES.get(ev_id, f"Unknown event {ev_id}")
    return ContactIDEvent(
        code=ev_id, partition=partition, zone=zone,
        client_id=client_id, message=message,
    )


def parse_contact_id_with_datetime(packet: bytes) -> ContactIDEvent | None:
    """Parse Contact ID event with datetime (0xB4). Returns ContactIDEvent or None."""
    if len(packet) != 29 or packet[1] not in (0x11, 0x12):
        return None
    client_id = bcd_to_decimal(packet[2:6])
    ev_id = bcd_to_decimal(packet[8:12])
    partition = bcd_to_decimal(packet[12:14]) - 1
    zone = bcd_to_decimal(packet[14:17])
    message = AMT_EVENT_MESSAGES.get(ev_id, f"Unknown event {ev_id}")

    try:
        event_time = datetime(
            2000 + packet[19], packet[18], packet[17],
            packet[20], packet[21], packet[22],
        )
    except (ValueError, OverflowError):
        event_time = None

    try:
        send_time = datetime(
            2000 + packet[25], packet[24], packet[23],
            packet[26], packet[27], packet[28],
        )
    except (ValueError, OverflowError):
        send_time = None

    return ContactIDEvent(
        code=ev_id, partition=partition, zone=zone,
        client_id=client_id, message=message,
        event_time=event_time, send_time=send_time,
    )


def parse_status_packet(packet: bytes) -> PanelStatus:
    """Parse ISECMobile status response (0xE9, >= 55 bytes). Returns PanelStatus."""
    status = PanelStatus()

    for x in range(6):
        for i in range(8):
            idx = x * 8 + i
            status.open_zones[idx] = bool((packet[x + 1] >> i) & 1)
            status.triggered_zones[idx] = bool((packet[x + 1 + 8] >> i) & 1)
            status.bypassed_zones[idx] = bool((packet[x + 1 + 16] >> i) & 1)

    # Partitions armed (bytes 28-29)
    c = packet[28]
    for i in range(2):
        status.partitions_armed[i] = bool((c >> i) & 1)
    c = packet[29]
    for i in range(2):
        status.partitions_armed[i + 2] = bool((c >> i) & 1)

    # Flags (byte 30)
    c = packet[30]
    status.problem_detected = bool((c >> 0) & 1)
    status.siren_activated = bool((c >> 1) & 1)
    status.panel_activated = bool((c >> 3) & 1)

    # Power (byte 36)
    c = packet[36]
    status.power_out = bool((c >> 0) & 1)
    status.battery_low = bool((c >> 1) & 1)
    status.battery_missing = bool((c >> 2) & 1)
    status.battery_short_circuit = bool((c >> 3) & 1)
    status.overload_aux = bool((c >> 4) & 1)

    # Communication errors (byte 43)
    c = packet[43]
    status.error_siren_cut = bool((c >> 0) & 1)
    status.error_siren_short_circuit = bool((c >> 1) & 1)
    status.error_telephone_line = bool((c >> 2) & 1)
    status.error_communicating_event = bool((c >> 3) & 1)

    return status


def parse_isecprogram_response(packet: bytes) -> tuple[int, bytes]:
    """Parse ISECProgram wrapper (0xE7). Returns (command, payload)."""
    # packet[0] = 0xE7, packet[1] = length, packet[2:] = payload + crc16
    if len(packet) < 4:
        return (0, b"")
    length = packet[1]
    payload = packet[2:2 + length]
    return (payload[0] if payload else 0, payload)


def parse_general_status_smart(payload: bytes) -> GeneralStatus:
    """Parse ISECProgram 0x27 response (Smart models, 134 bytes)."""
    gs = GeneralStatus()
    if len(payload) < 10:
        return gs

    gs.model_code = payload[1]
    gs.firmware_version = f"{payload[2]}.{payload[3]}.{payload[4]}"
    # Source voltage: bytes 5-6 (big-endian, x10 mV)
    gs.source_voltage = ((payload[5] << 8) | payload[6]) / 10.0
    # Battery voltage: bytes 7-8 (big-endian, x10 mV)
    gs.battery_voltage = ((payload[7] << 8) | payload[8]) / 10.0

    # Enabled zones: bytes 49-54 (6 bytes, 48 zones) in the extended response
    if len(payload) >= 55:
        for x in range(6):
            for i in range(8):
                idx = x * 8 + i
                gs.enabled_zones[idx] = bool((payload[49 + x] >> i) & 1)

    # PGM states: byte 9, up to 8 PGMs in basic response
    if len(payload) >= 10:
        pgm_byte = payload[9]
        gs.pgm_states = [bool((pgm_byte >> i) & 1) for i in range(8)]

    return gs


def parse_problem_status_smart(payload: bytes) -> ProblemStatus:
    """Parse ISECProgram 0x34 response (Smart models, 23 bytes)."""
    ps = ProblemStatus()
    if len(payload) < 23:
        return ps

    # Tamper per zone: bytes 1-6 (48 zones)
    for x in range(6):
        for i in range(8):
            ps.tamper_per_zone[x * 8 + i] = bool((payload[1 + x] >> i) & 1)

    # Short circuit per zone: bytes 7-12
    for x in range(6):
        for i in range(8):
            ps.short_circuit_per_zone[x * 8 + i] = bool((payload[7 + x] >> i) & 1)

    # Battery per wireless zone: bytes 13-18
    for x in range(6):
        for i in range(8):
            ps.battery_per_wireless_zone[x * 8 + i] = bool((payload[13 + x] >> i) & 1)

    # Bus problems: byte 19
    for i in range(8):
        ps.bus_problems[i] = bool((payload[19] >> i) & 1)

    return ps
