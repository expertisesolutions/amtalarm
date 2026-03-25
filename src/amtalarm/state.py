"""Mutable panel state, updated by status packets and Contact ID events."""

import logging

from .models import (
    PanelStatus,
    ContactIDEvent,
    DeviceInfo,
    GeneralStatus,
    ProblemStatus,
)
from .events import (
    AMT_EVENT_CODE_FALHA_AO_COMUNICAR_EVENTO,
    AMT_EVENT_MESSAGES,
    DEACTIVATION_EVENTS,
    ACTIVATION_EVENTS,
    TRIGGER_EVENTS,
    RESTORE_EVENTS,
)

MAX_SENSORS = 48
MAX_PARTITIONS = 4


class PanelState:
    """Mutable state of the alarm panel."""

    def __init__(self, logger: logging.Logger | None = None):
        self._logger = logger or logging.getLogger(__name__)
        self.device_info = DeviceInfo()
        self.status = PanelStatus()
        self.general_status: GeneralStatus | None = None
        self.problem_status: ProblemStatus | None = None
        self._enabled_zones: list[bool] = [True] * MAX_SENSORS

    def apply_status_packet(self, new_status: PanelStatus) -> None:
        """Apply a parsed status packet (from 0xE9 response) to state."""
        self.status = new_status

    def apply_contact_id_event(self, event: ContactIDEvent) -> None:
        """Apply a Contact ID event to update partition/trigger state."""
        code = event.code
        partition = event.partition
        zone = event.zone

        if code == AMT_EVENT_CODE_FALHA_AO_COMUNICAR_EVENTO:
            self._logger.error(
                "Alarm panel error: %s",
                AMT_EVENT_MESSAGES.get(code, f"Unknown {code}"),
            )

        if code in DEACTIVATION_EVENTS:
            if partition == -1:
                self.status.partitions_armed = [False] * MAX_PARTITIONS
                self.status.partitions_triggered = [False] * MAX_PARTITIONS
                self.status.triggered_zones = [False] * MAX_SENSORS
            else:
                self.status.partitions_armed[partition] = False
                self.status.partitions_triggered = [False] * MAX_PARTITIONS
                self.status.triggered_zones = [False] * MAX_SENSORS

        elif code in ACTIVATION_EVENTS:
            self._logger.info("Activated partition (untriggering too) %d", partition)
            if partition != -1 and zone != -1 and zone < MAX_SENSORS:
                self.status.triggered_zones[zone] = False
            if partition == -1:
                self.status.partitions_triggered = [False] * MAX_PARTITIONS
            else:
                self.status.partitions_triggered[partition] = False
            if partition == -1:
                self.status.partitions_armed = [True] * MAX_PARTITIONS
            else:
                self.status.partitions_armed[partition] = True

        if code in TRIGGER_EVENTS:
            self._logger.info("Triggering partition %d", partition)
            if partition != -1 and zone != -1 and zone < MAX_SENSORS:
                self.status.triggered_zones[zone] = True
            if partition == -1:
                self.status.partitions_triggered = [True] * MAX_PARTITIONS
            else:
                self.status.partitions_triggered[partition] = True

        if code in RESTORE_EVENTS:
            self._logger.info("Untriggering partition %d", partition)
            if partition != -1 and zone != -1 and zone < MAX_SENSORS:
                self.status.triggered_zones[zone] = False
            if partition == -1:
                self.status.partitions_triggered = [False] * MAX_PARTITIONS
            else:
                self.status.partitions_triggered[partition] = False

    def apply_general_status(self, gs: GeneralStatus) -> None:
        """Apply general status from ISECProgram."""
        self.general_status = gs
        self._enabled_zones = list(gs.enabled_zones)
        if gs.firmware_version:
            self.device_info.firmware_version = gs.firmware_version

    def apply_problem_status(self, ps: ProblemStatus) -> None:
        """Apply problem status from ISECProgram."""
        self.problem_status = ps

    def is_sensor_configured(self, index: int) -> bool:
        """Check if a zone is configured. True until first ISECProgram query."""
        if index < 0 or index >= MAX_SENSORS:
            return False
        return self._enabled_zones[index]
