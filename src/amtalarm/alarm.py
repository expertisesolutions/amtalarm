"""AMTAlarm: public API, orchestrates connection + state + polling + callbacks."""

import asyncio
import logging
import time
from typing import Callable

from .models import (
    ConnectionState,
    ContactIDEvent,
    DeviceInfo,
    GeneralStatus,
    PanelStatus,
    PanicType,
    ProblemStatus,
    SMART_MODEL_CODES,
)
from .events import (
    AMT_COMMAND_CODE_CONECTAR,
    AMT_COMMAND_CODE_HEARTBEAT,
    AMT_COMMAND_CODE_EVENT_CONTACT_ID,
    AMT_COMMAND_CODE_EVENT_DATA_HORA,
    AMT_COMMAND_CODE_SOLICITA_DATA_HORA,
    AMT_PROTOCOL_ISEC_MOBILE,
    AMT_PROTOCOL_ISECPROGRAM,
    AMT_REQ_CODE_MODELO,
    AMT_REQ_CODE_MAC,
    AMT_ISEC_MOBILE_COMMAND_CODE_COMAND_ACCEPTED,
    ISEC_MOBILE_ERROR_MESSAGES,
)
from .protocol import (
    encode_v1_frame,
    encode_isecprogram_frame,
    build_request_model,
    build_request_zones,
    build_arm,
    build_arm_partition,
    build_disarm,
    build_disarm_partition,
    build_trigger,
    build_bypass,
    build_datetime_response,
    build_isecprogram_auth,
    build_isecprogram_close,
    build_isecprogram_general_status_smart,
    build_isecprogram_general_status_legacy,
    build_isecprogram_problem_status_smart,
    build_isecprogram_problem_status_legacy,
    parse_model_response,
    parse_connect,
    parse_connect_complementary,
    parse_contact_id,
    parse_contact_id_with_datetime,
    parse_status_packet,
    parse_isecprogram_response,
    parse_general_status_smart,
    parse_problem_status_smart,
    xor_checksum,
)
from .connection import AMTConnection
from .state import PanelState, MAX_SENSORS, MAX_PARTITIONS


class AMTAlarm:
    """Public API for the AMT alarm panel."""

    def __init__(
        self,
        port: int,
        default_password=None,
        logger: logging.Logger | None = None,
    ):
        self._logger = logger or logging.getLogger(__name__)
        self.default_password: str | None = None
        if default_password is not None:
            self.default_password = str(default_password)
            if len(self.default_password) not in (4, 6):
                raise ValueError("Password must be 4 or 6 digits")

        self._port = port
        self._state = PanelState(self._logger)
        self._connection = AMTConnection(port, self._handle_packet, self._logger)

        # Events for initialization flow
        self._model_initialized = asyncio.Event()
        self._initialized = asyncio.Event()

        # ISECProgram
        self._isecprogram_lock = asyncio.Lock()
        self._isecprogram_response: asyncio.Event = asyncio.Event()
        self._isecprogram_authenticated = False
        self._isecprogram_last_response: bytes = b""

        # Callbacks
        self._status_callbacks: list[Callable] = []
        self._event_callbacks: list[Callable] = []
        self._listeners: list = []  # compat: objects with alarm_update()

        # Polling
        self._polling_task: asyncio.Task | None = None
        self._problem_polling_task: asyncio.Task | None = None

        # Reconnection supervisor
        self._closing = False
        self._connecting = False
        self._reconnect_task: asyncio.Task | None = None
        self._connection.on_connection_change(self._handle_connection_state)

    # --- Properties (read-only state) ---

    @property
    def device_info(self) -> DeviceInfo:
        return self._state.device_info

    @property
    def status(self) -> PanelStatus:
        return self._state.status

    @property
    def general_status(self) -> GeneralStatus | None:
        return self._state.general_status

    @property
    def problem_status(self) -> ProblemStatus | None:
        return self._state.problem_status

    @property
    def connection_state(self) -> ConnectionState:
        return self._connection.state

    # --- Compat properties (delegate to state/device_info) ---

    @property
    def model(self) -> str:
        return self._state.device_info.model

    @property
    def mac_address(self) -> bytes:
        return self._state.device_info.mac_address

    @property
    def _mac_address(self) -> bytes:
        """Alias for mac_address (compat)."""
        return self._state.device_info.mac_address

    @property
    def partitions(self) -> list:
        return self._state.status.partitions_armed

    @property
    def triggered_partitions(self) -> list:
        return self._state.status.partitions_triggered

    @property
    def open_sensors(self) -> list:
        return self._state.status.open_zones

    @property
    def bypassed_sensors(self) -> list:
        return self._state.status.bypassed_zones

    @property
    def max_sensors(self) -> int:
        return MAX_SENSORS

    @property
    def max_partitions(self) -> int:
        return MAX_PARTITIONS

    def is_sensor_configured(self, index: int) -> bool:
        return self._state.is_sensor_configured(index)

    def is_partition_configured(self, index: int) -> bool:
        return True

    # --- Connection lifecycle ---

    async def start(self) -> None:
        """Create TCP server, wait for panel connection, start polling."""
        self._initialized.clear()
        self._model_initialized.clear()
        self._state.status = PanelStatus()

        await self._connection.start()
        self._call_listeners()

    async def stop(self) -> None:
        """Shutdown cleanly."""
        self._closing = True
        self._cancel_reconnect()
        if self._problem_polling_task is not None:
            self._problem_polling_task.cancel()
            self._problem_polling_task = None
        self._connection.close()

    # Compat (deprecated, delegate to start/stop)
    async def wait_connection(self) -> bool:
        await self.start()
        self._call_listeners()
        return True

    async def wait_connection_and_update(self) -> None:
        self._closing = False
        await self._connect_and_update()

    def close(self) -> None:
        self._closing = True
        self._cancel_reconnect()
        self._connection.close()

    def _cancel_reconnect(self) -> None:
        if self._reconnect_task is not None:
            self._reconnect_task.cancel()
            self._reconnect_task = None

    async def _connect_and_update(self) -> None:
        if self._connecting:
            return
        self._connecting = True
        try:
            while not self._closing:
                try:
                    await self.wait_connection()
                    await self.async_update()
                    return
                except asyncio.CancelledError:
                    raise
                except Exception as ex:
                    self._logger.error("Connect/update failed, retrying in 2s: %s", ex)
                    await asyncio.sleep(2)
        finally:
            self._connecting = False

    def _handle_connection_state(self, state) -> None:
        if (state == ConnectionState.DISCONNECTED
                and not self._closing
                and not self._connecting
                and (self._reconnect_task is None or self._reconnect_task.done())):
            self._logger.warning("Panel connection lost, scheduling automatic reconnect")
            self._reconnect_task = asyncio.create_task(self._connect_and_update())

    async def async_update(self) -> None:
        """Start polling and reading tasks."""
        self._connection.start_tasks(self._polling_loop)
        await asyncio.wait_for(self._initialized.wait(), timeout=30)
        await asyncio.wait_for(self._model_initialized.wait(), timeout=30)

        if self.default_password is not None:
            asyncio.create_task(self._initial_isecprogram_query())

    # --- Callbacks ---

    def on_status_update(self, callback: Callable[[PanelStatus], None]) -> Callable:
        self._status_callbacks.append(callback)
        def unsub():
            if callback in self._status_callbacks:
                self._status_callbacks.remove(callback)
        return unsub

    def on_event(self, callback: Callable[[ContactIDEvent], None]) -> Callable:
        self._event_callbacks.append(callback)
        def unsub():
            if callback in self._event_callbacks:
                self._event_callbacks.remove(callback)
        return unsub

    def on_connection_change(self, callback: Callable[[ConnectionState], None]) -> Callable:
        return self._connection.on_connection_change(callback)

    # Compat listener
    def listen_event(self, listener) -> None:
        if listener not in self._listeners:
            self._listeners.append(listener)

    def remove_listen_event(self, listener) -> None:
        if listener in self._listeners:
            self._listeners.remove(listener)

    def _call_listeners(self) -> None:
        for listener in self._listeners:
            try:
                listener.alarm_update()
            except Exception:
                self._logger.exception("Error in listener callback")
        for cb in self._status_callbacks:
            try:
                cb(self._state.status)
            except Exception:
                self._logger.exception("Error in status callback")

    def _call_event_callbacks(self, event: ContactIDEvent) -> None:
        for cb in self._event_callbacks:
            try:
                cb(event)
            except Exception:
                self._logger.exception("Error in event callback")

    # --- Commands ---

    async def _send_packet(self, packet: bytes) -> None:
        """Encode and send an IsecNet V1 frame."""
        await self._connection.send_raw(encode_v1_frame(packet))

    async def send_request_zones(self) -> None:
        if self.default_password is None:
            raise ValueError("Password required")
        await self._send_packet(build_request_zones(self.default_password))

    async def send_arm(self, code=None) -> None:
        code = code or self.default_password
        if code is None:
            raise ValueError("Password required")
        self._logger.info("arm")
        await self._send_packet(build_arm(code))

    async def send_arm_partition(self, partition: int, code=None) -> None:
        code = code or self.default_password
        if code is None:
            raise ValueError("Password required")
        self._logger.info("arm partition %d", partition + 1)
        await self._send_packet(build_arm_partition(partition, code))

    async def send_disarm(self, code=None) -> None:
        code = code or self.default_password
        if code is None:
            raise ValueError("Password required")
        self._logger.info("disarm")
        frame = encode_v1_frame(build_disarm(code))
        await self._connection.send_raw(frame)

    async def send_disarm_partition(self, partition: int, code=None) -> None:
        code = code or self.default_password
        if code is None:
            raise ValueError("Password required")
        self._logger.info("disarm partition %d", partition + 1)
        frame = encode_v1_frame(build_disarm_partition(partition, code))
        await self._connection.send_raw(frame)

    async def _send_trigger(self, code=None, panic_type=PanicType.AUDIBLE) -> None:
        code = code or self.default_password
        if code is None:
            raise ValueError("Password required")
        await self._send_packet(build_trigger(code, panic_type))

    async def send_audible_trigger(self, code=None) -> None:
        self._logger.debug("send audible trigger")
        await self._send_trigger(code, PanicType.AUDIBLE)

    async def send_silent_trigger(self, code=None) -> None:
        self._logger.debug("send silent trigger")
        await self._send_trigger(code, PanicType.SILENT)

    async def send_medical_trigger(self, code=None) -> None:
        self._logger.debug("send medical trigger")
        await self._send_trigger(code, PanicType.MEDICAL)

    async def send_fire_trigger(self, code=None) -> None:
        self._logger.debug("send fire trigger")
        await self._send_trigger(code, PanicType.FIRE)

    async def send_bypass(self, zones: list[int], code=None) -> None:
        code = code or self.default_password
        if code is None:
            raise ValueError("Password required")
        self._logger.debug("send bypass")
        await self._send_packet(build_bypass(zones, code))

    # --- ISECProgram commands ---

    async def _isecprogram_session(self, command_builder, response_parser=None):
        """Run an ISECProgram command within an auth session (locks keyboard)."""
        if self.default_password is None:
            return None

        async with self._isecprogram_lock:
            try:
                # Auth
                self._isecprogram_response.clear()
                self._isecprogram_authenticated = False
                await self._connection.send_raw(
                    encode_isecprogram_frame(build_isecprogram_auth(self.default_password))
                )
                try:
                    await asyncio.wait_for(self._isecprogram_response.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    self._logger.warning("ISECProgram auth timeout")
                    return None

                if not self._isecprogram_authenticated:
                    self._logger.warning("ISECProgram auth failed")
                    return None

                # Send command
                self._isecprogram_response.clear()
                self._isecprogram_last_response = b""
                await self._connection.send_raw(
                    encode_isecprogram_frame(command_builder())
                )
                try:
                    await asyncio.wait_for(self._isecprogram_response.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    self._logger.warning("ISECProgram command timeout")
                    return None

                if response_parser and self._isecprogram_last_response:
                    return response_parser(self._isecprogram_last_response)
                return self._isecprogram_last_response

            finally:
                # Always close session (unlocks keyboard)
                await self._connection.send_raw(
                    encode_isecprogram_frame(build_isecprogram_close())
                )

    async def request_general_status(self) -> GeneralStatus | None:
        """Request general status via ISECProgram."""
        is_smart = self._state.device_info.model_code in SMART_MODEL_CODES
        builder = build_isecprogram_general_status_smart if is_smart else build_isecprogram_general_status_legacy
        parser = parse_general_status_smart  # TODO: add legacy parser
        result = await self._isecprogram_session(builder, parser)
        if result and isinstance(result, GeneralStatus):
            self._state.apply_general_status(result)
            self._call_listeners()
            return result
        return None

    async def request_problem_status(self) -> ProblemStatus | None:
        """Request problem status via ISECProgram."""
        is_smart = self._state.device_info.model_code in SMART_MODEL_CODES
        builder = build_isecprogram_problem_status_smart if is_smart else build_isecprogram_problem_status_legacy
        parser = parse_problem_status_smart  # TODO: add legacy parser
        result = await self._isecprogram_session(builder, parser)
        if result and isinstance(result, ProblemStatus):
            self._state.apply_problem_status(result)
            self._call_listeners()
            return result
        return None

    async def _initial_isecprogram_query(self) -> None:
        """Run initial ISECProgram queries after connection."""
        try:
            await self.request_general_status()
        except Exception:
            self._logger.exception("Initial general status query failed")

        # Start periodic problem status polling
        self._problem_polling_task = asyncio.create_task(self._problem_polling_loop())

    async def _problem_polling_loop(self) -> None:
        """Poll problem status every 60 seconds."""
        while True:
            await asyncio.sleep(60)
            try:
                await self.request_problem_status()
            except asyncio.CancelledError:
                return
            except Exception:
                self._logger.exception("Problem status poll failed")

    # --- Polling ---

    async def _polling_loop(self) -> None:
        """Poll zone status every second."""
        if self.default_password is None:
            return
        while True:
            try:
                await self.send_request_zones()
                await asyncio.sleep(1)
                if self._connection.check_timeout():
                    self._logger.error("Read timeout exceeded")
                    await self._connection._accept_new_connection()
                    return
            except OSError as ex:
                self._logger.error("Connection error in polling: %s", ex)
                await self._connection._accept_new_connection()
                return
            except asyncio.CancelledError:
                return
            except Exception as ex:
                self._logger.error("Unknown error in polling: %s", ex)
                await self._connection._accept_new_connection()
                raise

    # --- Packet handler ---

    async def _handle_packet(self, packet: bytes) -> None:
        """Handle a complete, validated packet from the connection layer."""
        self._logger.debug("received packet %s", packet.hex())
        if len(packet) == 0:
            return

        cmd = packet[0]

        if cmd == AMT_REQ_CODE_MODELO and len(packet) > 1:
            self._state.device_info.model = parse_model_response(packet)
            self._model_initialized.set()
            self._logger.debug("Model: %s", self._state.device_info.model)

        elif cmd == AMT_COMMAND_CODE_HEARTBEAT:
            await self._connection.send_ack()

        elif cmd == AMT_COMMAND_CODE_CONECTAR:
            if len(self._state.device_info.mac_address) == 0:
                self._state.device_info.mac_address = parse_connect(packet)
            self._logger.debug("MAC: %s", self._state.device_info.mac_address.hex())
            self._initialized.set()
            await self._connection.send_ack()
            await self._send_packet(build_request_model())

        elif cmd == AMT_REQ_CODE_MAC and len(packet) == 7:
            self._state.device_info.mac_address = packet[1:7]

        elif cmd == AMT_COMMAND_CODE_EVENT_CONTACT_ID:
            event = parse_contact_id(packet)
            if event:
                self._state.apply_contact_id_event(event)
                self._call_listeners()
                self._call_event_callbacks(event)
                await self._connection.send_ack()
            else:
                self._logger.warning(
                    "Contact ID event unparseable, size %d", len(packet)
                )

        elif cmd == AMT_COMMAND_CODE_EVENT_DATA_HORA:
            event = parse_contact_id_with_datetime(packet)
            if event:
                self._logger.info(
                    "event %d from partition %d zone %d time %s",
                    event.code, event.partition, event.zone, event.event_time,
                )
                self._state.apply_contact_id_event(event)
                self._call_listeners()
                self._call_event_callbacks(event)
                await self._connection.send_ack()
            else:
                self._logger.warning(
                    "Contact ID datetime event unparseable, size %d", len(packet)
                )

        elif cmd == AMT_COMMAND_CODE_SOLICITA_DATA_HORA:
            self._logger.info("sending datetime response to alarm panel")
            timezone_offset = packet[1] if len(packet) > 1 else 0
            response = build_datetime_response(cmd, timezone_offset)
            await self._send_packet(response)

        elif cmd == AMT_PROTOCOL_ISECPROGRAM and len(packet) >= 4:
            # ISECProgram response
            if packet[1] == 1 and packet[2] == 0x50:
                # Auth accepted
                self._isecprogram_authenticated = True
                self._isecprogram_response.set()
            elif packet[1] == 1 and packet[2] == 0x53:
                # Auth rejected
                self._logger.error("ISECProgram authentication failed")
                self._isecprogram_authenticated = False
                self._isecprogram_response.set()
            elif packet[1] == 1 and packet[2] == 0x95:
                # Session closed (response to 0x15)
                pass
            else:
                # Data response — store for the waiting command
                self._isecprogram_last_response = packet[2:2 + packet[1]]
                self._isecprogram_response.set()

        elif cmd == AMT_PROTOCOL_ISEC_MOBILE and len(packet) == 2:
            if packet[1] == AMT_ISEC_MOBILE_COMMAND_CODE_COMAND_ACCEPTED:
                await self._connection.send_ack()
            else:
                msg = ISEC_MOBILE_ERROR_MESSAGES.get(
                    packet[1], f"Unknown ISECMobile error 0x{packet[1]:02x}"
                )
                self._logger.error("ISECMobile error: %s", msg)
                await self._connection.send_ack()

        elif cmd == AMT_PROTOCOL_ISEC_MOBILE and len(packet) >= 55:
            # Status update
            new_status = parse_status_packet(packet)
            self._state.apply_status_packet(new_status)

            if new_status.siren_activated or new_status.problem_detected:
                self._logger.warning(
                    "siren=%s panel_activated=%s problem=%s",
                    new_status.siren_activated,
                    new_status.panel_activated,
                    new_status.problem_detected,
                )
            if new_status.overload_aux or new_status.battery_short_circuit or new_status.battery_missing or new_status.battery_low or new_status.power_out:
                self._logger.warning(
                    "overload_aux=%s battery_short=%s battery_missing=%s battery_low=%s power_out=%s",
                    new_status.overload_aux,
                    new_status.battery_short_circuit,
                    new_status.battery_missing,
                    new_status.battery_low,
                    new_status.power_out,
                )
            if new_status.error_communicating_event or new_status.error_telephone_line or new_status.error_siren_short_circuit or new_status.error_siren_cut:
                self._logger.warning(
                    "error: comm=%s phone=%s siren_short=%s siren_cut=%s",
                    new_status.error_communicating_event,
                    new_status.error_telephone_line,
                    new_status.error_siren_short_circuit,
                    new_status.error_siren_cut,
                )

            self._connection._set_state(ConnectionState.READY)
            self._call_listeners()

        else:
            self._logger.error("Unknown packet: %s", packet.hex())
