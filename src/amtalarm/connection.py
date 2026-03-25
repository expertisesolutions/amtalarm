"""TCP server, accept loop, read stream, frame reassembly for IsecNet V1."""

import asyncio
import logging
import socket
import time
from typing import Callable

from .models import ConnectionState
from .protocol import xor_checksum


class AMTConnection:
    """Manages TCP connection to the alarm panel."""

    def __init__(
        self,
        port: int,
        packet_handler: Callable,
        logger: logging.Logger | None = None,
    ):
        self._port = port
        self._packet_handler = packet_handler
        self._logger = logger or logging.getLogger(__name__)
        self._timeout = 20.0

        self._socket: socket.socket | None = None
        self._client_socket: socket.socket | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._reader: asyncio.StreamReader | None = None

        self._outstanding_buffer = bytes()
        self._read_timestamp: float | None = None
        self._polling_task: asyncio.Task | None = None
        self._reading_task: asyncio.Task | None = None

        self._state = ConnectionState.DISCONNECTED
        self._state_callbacks: list[Callable] = []

    @property
    def state(self) -> ConnectionState:
        return self._state

    def _set_state(self, new_state: ConnectionState) -> None:
        if self._state != new_state:
            self._state = new_state
            for cb in self._state_callbacks:
                try:
                    cb(new_state)
                except Exception:
                    self._logger.exception("Error in connection state callback")

    def on_connection_change(self, callback: Callable) -> Callable:
        """Register callback for connection state changes. Returns unsubscribe callable."""
        self._state_callbacks.append(callback)
        def unsubscribe():
            if callback in self._state_callbacks:
                self._state_callbacks.remove(callback)
        return unsubscribe

    async def send_raw(self, data: bytes) -> None:
        """Send raw bytes to the panel."""
        if self._writer is None:
            self._logger.error("Cannot send: not connected")
            return
        try:
            self._logger.debug("sending %s", data.hex())
            self._writer.write(data)
            await self._writer.drain()
        except OSError as e:
            self._logger.error("Connection error sending: %s", e)
            await self._accept_new_connection()
        except Exception as e:
            self._logger.error("Unknown error sending: %s", e)
            await self._accept_new_connection()
            raise

    async def send_ack(self) -> None:
        """Send ACK byte (0xFE)."""
        await self.send_raw(bytes([0xFE]))

    async def start(self) -> None:
        """Create TCP server and wait for first connection from panel."""
        self._outstanding_buffer = bytes()

        self.close()
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._socket.setblocking(False)
        self._socket.bind(("", self._port))
        self._socket.listen(1)

        self._set_state(ConnectionState.LISTENING)

        loop = asyncio.get_running_loop()
        while True:
            try:
                (self._client_socket, addr) = await asyncio.wait_for(
                    loop.sock_accept(self._socket), timeout=600
                )
                self._logger.debug("Connection accepted from %s", addr)
            except asyncio.TimeoutError:
                self._logger.error("Timeout waiting for connection (600s). Retrying")
                continue
            try:
                (self._reader, self._writer) = await asyncio.open_connection(
                    None, sock=self._client_socket
                )
            except asyncio.TimeoutError:
                self._logger.error("Timeout opening stream. Retrying")
                continue

            self._set_state(ConnectionState.CONNECTED)
            break

    def start_tasks(self, polling_coro) -> None:
        """Start reading and polling tasks."""
        if self._reading_task is None:
            self._reading_task = asyncio.create_task(self._read_loop())
        if self._polling_task is None and polling_coro is not None:
            self._polling_task = asyncio.create_task(polling_coro())

    def close(self) -> None:
        """Close all sockets and cancel tasks."""
        if self._polling_task is not None:
            self._polling_task.cancel()
            self._polling_task = None
        if self._reading_task is not None:
            self._reading_task.cancel()
            self._reading_task = None
        if self._writer is not None:
            self._writer.close()
            self._writer = None
        if self._client_socket is not None:
            self._client_socket.close()
            self._client_socket = None
        if self._socket is not None:
            self._socket.close()
            self._socket = None
        self._set_state(ConnectionState.DISCONNECTED)

    def check_timeout(self) -> bool:
        """Check if read timeout has been exceeded. Returns True if timed out."""
        if self._read_timestamp is not None and time.monotonic() - self._read_timestamp >= self._timeout:
            return True
        return False

    async def _accept_new_connection(self) -> None:
        """Drop current connection and accept a new one."""
        self._read_timestamp = None
        if self._polling_task is not None:
            self._polling_task.cancel()
            self._polling_task = None
        if self._reading_task is not None:
            self._reading_task.cancel()
            self._reading_task = None
        if self._client_socket is not None:
            self._client_socket.close()
            self._client_socket = None

        self._set_state(ConnectionState.DISCONNECTED)
        # The alarm.py orchestrator will handle reconnection via its own task

    @property
    def needs_reconnect(self) -> bool:
        """True if connection was dropped and needs reconnecting."""
        return self._state == ConnectionState.DISCONNECTED and self._socket is not None

    async def _read_loop(self) -> None:
        """Read data from stream and reassemble frames."""
        while True:
            self._read_timestamp = time.monotonic()
            try:
                data = await self._reader.read(4096)
            except (OSError, ConnectionError) as e:
                self._logger.error("Read error: %s", e)
                await self._accept_new_connection()
                return

            if self._reader.at_eof():
                self._logger.info("Connection dropped by panel")
                await self._accept_new_connection()
                return

            self._outstanding_buffer += data

            try:
                await self._process_buffer()
            except Exception as e:
                self._logger.error("Error processing data: %s", e)
                await self._accept_new_connection()
                raise

    async def _process_buffer(self) -> None:
        """Extract complete frames from the outstanding buffer."""
        while len(self._outstanding_buffer) != 0:
            is_heartbeat = self._outstanding_buffer[0] == 0xF7

            if is_heartbeat:
                # Heartbeat: single byte, no checksum
                self._outstanding_buffer = self._outstanding_buffer[1:]
                await self._packet_handler(bytes([0xF7]))
                continue

            if self._outstanding_buffer[0] == 0:
                break

            packet_size = self._outstanding_buffer[0]

            # Need: 1 (length) + packet_size + 1 (checksum)
            if len(self._outstanding_buffer) < packet_size + 2:
                break

            frame = self._outstanding_buffer[:packet_size + 2]
            # Validate checksum
            if xor_checksum(frame) != 0:
                self._logger.debug(
                    "Checksum mismatch on frame %s, dropping 1 byte",
                    frame.hex(),
                )
                self._outstanding_buffer = self._outstanding_buffer[1:]
                continue

            # Valid frame: extract payload (skip length byte, strip checksum)
            payload = frame[1:-1]
            self._outstanding_buffer = self._outstanding_buffer[packet_size + 2:]

            if len(payload) > 0:
                await self._packet_handler(payload)
