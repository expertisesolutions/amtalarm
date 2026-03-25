"""Dataclasses and enums for AMT alarm protocol."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum, auto


class PanicType(IntEnum):
    SILENT = 0
    AUDIBLE = 1
    MEDICAL = 2
    FIRE = 3


class ConnectionState(IntEnum):
    DISCONNECTED = auto()
    LISTENING = auto()
    CONNECTED = auto()
    READY = auto()


# Model codes from handshake 0x95
AMT_MODEL_CODES = {
    0x00: "AMT 2008 RF",
    0x03: "AMT 2010",
    0x04: "AMT 2018",
    0x09: "AMT 4010",
    0x0A: "AMT 2018 E",
    0x0B: "AMT 2018 EG",
    0x14: "AMT 4010 Smart",
    0x15: "AMT 1000 Smart",
    0x1E: "AMT 2018 E/EG",
    0x29: "XEG 4000 Smart",
    0x41: "AMT 4010",
}

# Smart series models that use 0x27/0x34 instead of 0x17/0x14
SMART_MODEL_CODES = {0x14, 0x15, 0x29}


@dataclass
class DeviceInfo:
    model: str = ""
    model_code: int = 0
    mac_address: bytes = b""
    firmware_version: str = ""


@dataclass
class PanelStatus:
    # Zones (48)
    open_zones: list = field(default_factory=lambda: [None] * 48)
    triggered_zones: list = field(default_factory=lambda: [False] * 48)
    bypassed_zones: list = field(default_factory=lambda: [None] * 48)
    # Partitions (4)
    partitions_armed: list = field(default_factory=lambda: [None] * 4)
    partitions_triggered: list = field(default_factory=lambda: [False] * 4)
    # Flags (byte 30)
    siren_activated: bool = False
    panel_activated: bool = False
    problem_detected: bool = False
    # Power (byte 36)
    power_out: bool = False
    battery_low: bool = False
    battery_missing: bool = False
    battery_short_circuit: bool = False
    overload_aux: bool = False
    # Communication errors (byte 43)
    error_communicating_event: bool = False
    error_telephone_line: bool = False
    error_siren_short_circuit: bool = False
    error_siren_cut: bool = False


@dataclass
class ContactIDEvent:
    code: int = 0
    partition: int = -1  # 0-based, -1 = all
    zone: int = 0
    client_id: int = 0
    message: str = ""
    event_time: datetime | None = None
    send_time: datetime | None = None


@dataclass
class GeneralStatus:
    """From ISECProgram 0x27 (Smart) or 0x17 (non-Smart)."""
    model_code: int = 0
    firmware_version: str = ""
    source_voltage: float = 0.0
    battery_voltage: float = 0.0
    pgm_states: list = field(default_factory=list)
    enabled_zones: list = field(default_factory=lambda: [True] * 48)


@dataclass
class ProblemStatus:
    """From ISECProgram 0x34 (Smart) or 0x14 (non-Smart)."""
    tamper_per_zone: list = field(default_factory=lambda: [False] * 48)
    short_circuit_per_zone: list = field(default_factory=lambda: [False] * 48)
    battery_per_wireless_zone: list = field(default_factory=lambda: [False] * 48)
    bus_problems: list = field(default_factory=lambda: [False] * 8)
