import asyncio
import socket
import time
from typing import Union
import sys
import logging

LOGGER = logging.getLogger(__package__)

AMT_COMMAND_CODE_CONECTAR = 0x94
# Data:
# Byte 1- channel (0x45 - ethernet, 0x47 - sim card 1, 0x48 - sim card 2)
# Byte 2 to 3 - account (each nibble is an account digit (0 is 0xA))
# Byte 4 to 6 - partial MAC address (last three bytes)
AMT_COMMAND_CODE_HEARTBEAT = 0xF7
AMT_COMMAND_CODE_CONECTA_E_COMPLEMENTAR = 0x95
# Byte 1 - channel
# Byte 2 to 3 - account
# Byte 4 to 9 - complete MAC address
# Byte 10 - model (0x1E - 2018 E/EG, 0x41 - AMT 4010 etc)
# Byte 11 to 13 - Firmware version (x.x.x format)
# Byte 14 to 28 - IMEI (IMEI of GPRS/3G/4G module installed, 0x00 if not installed)
# Byte 29 to 48 - Chip ID (SIM card ID installed on model, 0x00 if not installed)
AMT_COMMAND_CODE_EVENT_CONTACT_ID = 0xB0
# Byte 1 - CH/IP
# Byte 2 to 5 - account
# Byte 6 to 7 - MT (?)
# Byte 8 - Q (?)
# Byte 9 to 11 - event code (?)
# Byte 12 to 13 - partition
# Byte 14 to 16 - zone
AMT_COMMAND_CODE_EVENT_DATA_HORA = 0xB4
# Byte 1 - CH/IP
# Byte 2 to 5 - account
# Byte 6 to 7 - MT (?)
# Byte 8 - Q (?)
# Byte 9 to 11 - event code (?)
# Byte 12 to 13 - partition
# Byte 14 to 16 - zone
# Byte 17 to 19 - event date dd/mm/yy format
# Byte 20 to 22 - event hour hh:MM:ss format
# Byte 23 to 25 - send date dd/mm/yy format
# Byte 26 to 28 - send hour hh:MM:ss format
AMT_COMMAND_CODE_EVENT_FOTO_ASSOCIADA = 0xB5
# Byte 1 - CH/IP
# Byte 2 to 5 - account
# Byte 6 to 7 - MT (?)
# Byte 8 - Q (?)
# Byte 9 to 11 - event code (?)
# Byte 12 to 13 - partition
# Byte 14 to 16 - zone
AMT_COMMAND_CODE_SOLICITA_DATA_HORA = 0x80
# Byte 1 - time zone (optional)

AMT_REQ_CODE_VERSAO_FIRMWARE = 0xC0
AMT_REQ_CODE_MODELO = 0xC2
AMT_REQ_CODE_MAC = 0xC4
AMT_REQ_CODE_IMEI = 0xC5
AMT_REQ_CODE_ICCD_CHIP = 0xC6
AMT_REQ_CODE_NIVEL_SINAL_GPRS3G4G = 0xD1
AMT_REQ_CODE_PRESENCA_MODULO_GPRS3G4G = 0xD3

AMT_PROTOCOL_ISEC_MOBILE = 0xE9
# Byte 1 - 0x21 (start of frame)
# Byte 2 to 5 or 2 to 7 - password
# Byte 6 or 8 - command
# Byte 7 or 9 to ... - content
# Byte ... + 1 - 0x21 (end of frame)


AMT_EVENT_CODE_EMERGENCIA_MEDICA = 1100
AMT_EVENT_CODE_DISPARO_OU_PANICO_DE_INCENDIO = 1110
AMT_EVENT_CODE_PANICO_AUDIVEL_OU_SILENCIOSO = 1120
AMT_EVENT_CODE_SENHA_DE_COACAO = 1121
AMT_EVENT_CODE_PANICO_SILENCIOSO = 1122
AMT_EVENT_CODE_DISPARO_DE_ZONA = 1130
AMT_EVENT_CODE_DISPARO_DE_CERCA_ELETRICA = 1131
AMT_EVENT_CODE_DISPARO_DE_ZONA_24H = 1133
AMT_EVENT_CODE_TAMPER_DO_TECLADO = 1145
AMT_EVENT_CODE_DISPARO_SILENCIOSO = 1146
AMT_EVENT_CODE_FALHA_DA_SUPERVISAO_SMART = 1147
AMT_EVENT_CODE_SOBRECARGA_NA_SAIDA_AUXILIAR = 1300
AMT_EVENT_CODE_FALHA_NA_REDE_ELETRICA = 1301
AMT_EVENT_CODE_BATERIA_PRINCIPAL_BAIXA_OU_EM_CURTO_CIRCUITO = 1302
AMT_EVENT_CODE_RESET_PELO_MODO_DE_PROGRAMACAO = 1305
AMT_EVENT_CODE_ALTERACAO_DA_PROGRAMACAO_DO_PAINEL = 1306
AMT_EVENT_CODE_BATERIA_PRINCIPAL_AUSENTE_OU_INVERTIDA = 1311
AMT_EVENT_CODE_CORTE_OU_CURTO_CIRCUITO_NA_SIRENE = 1321
AMT_EVENT_CODE_TOQUE_DE_PORTEIRO = 1322
AMT_EVENT_CODE_PROBLEMA_EM_TECLADO_OU_RECEPTOR = 1333
AMT_EVENT_CODE_FALHA_NA_LINHA_TELEFONICA = 1351
AMT_EVENT_CODE_FALHA_AO_COMUNICAR_EVENTO = 1354
AMT_EVENT_CODE_CORTE_DA_FIACAO_DOS_SENSORES = 1371
AMT_EVENT_CODE_CURTO_CIRCUITO_NA_FIACAO_DOS_SENSORES = 1372
AMT_EVENT_CODE_TAMPER_DO_SENSOR = 1383
AMT_EVENT_CODE_BATERIA_BAIXA_DE_SENSOR_SEM_FIO = 1384
AMT_EVENT_CODE_DESATIVACAO_PELO_USUARIO = 1401
AMT_EVENT_CODE_AUTO_DESATIVACAO = 1403
AMT_EVENT_CODE_DESATIVACAO_VIA_COMPUTADOR_OU_TELEFONE = 1407
AMT_EVENT_CODE_ACESSO_REMOTO_PELO_SOFTWARE_DE_DOWNLOAD_UPLOAD = 1410
AMT_EVENT_CODE_FALHA_NO_DOWNLOAD = 1413
AMT_EVENT_CODE_ACIONAMENTO_DE_PGM = 1422
AMT_EVENT_CODE_SENHA_INCORRETA = 1461
AMT_EVENT_CODE_ANULACAO_TEMPORARIA_DE_ZONA = 1570
AMT_EVENT_CODE_ANULACAO_POR_DISPARO = 1573
AMT_EVENT_CODE_TESTE_MANUAL = 1601
AMT_EVENT_CODE_TESTE_PERIODICO = 1602
AMT_EVENT_CODE_SOLICITACAO_DE_MANUTENCAO = 1616
AMT_EVENT_CODE_RESET_DO_BUFFER_DE_EVENTOS = 1621
AMT_EVENT_CODE_LOG_DE_EVENTOS_CHEIO = 1624
AMT_EVENT_CODE_DATA_E_HORA_FORAM_REINICIADAS = 1625
AMT_EVENT_CODE_RESTAURACAO_DE_INCENDIO = 3110
AMT_EVENT_CODE_RESTAURACAO_DISPARO_DE_ZONA = 3130
AMT_EVENT_CODE_RESTAURACAO_DE_DISPARO_DE_CERCA_ELETRICA = 3131
AMT_EVENT_CODE_RESTARAUCAO_DISPARO_DE_ZONA_24H = 3133
AMT_EVENT_CODE_RESTARAUCAO_TAMPER_DO_TECLADO = 3145
AMT_EVENT_CODE_RESTARAUCAO_DISPARO_SILENCIOSO = 3146
AMT_EVENT_CODE_RESTARAUCAO_DA_SUPERVISAO_SMART = 3147
AMT_EVENT_CODE_RESTARAUCAO_SOBRECARGA_NA_SAIDA_AUXILIAR = 3300
AMT_EVENT_CODE_RESTARAUCAO_FALHA_NA_REDE_ELETRICA = 3301
AMT_EVENT_CODE_RESTARAUCAO_BAT_PRINC_BAIXA_OU_EM_CURTO_CIRCUITO = 3302
AMT_EVENT_CODE_RESTARAUCAO_BAT_PRINC_AUSENTE_OU_INVERTIDA = 3311
AMT_EVENT_CODE_RESTARAUCAO_CORTE_OU_CURTO_CIRCUITO_NA_SIRENE = 3321
AMT_EVENT_CODE_RESTARAUCAO_PROBLEMA_EM_TECLADO_OU_RECEPTOR = 3333
AMT_EVENT_CODE_RESTARAUCAO_LINHA_TELEFONICA = 3351
AMT_EVENT_CODE_RESTARAUCAO_CORTE_DA_FIACAO_DOS_SENSORES = 3371
AMT_EVENT_CODE_RESTARAUCAO_CURTO_CIRCUITO_NA_FIACAO_DOS_SENSORES = 3372
AMT_EVENT_CODE_RESTARAUCAO_TAMPER_DO_SENSOR = 3383
AMT_EVENT_CODE_RESTARAUCAO_BATERIA_BAIXA_DE_SENSOR_SEM_FIO = 3384
AMT_EVENT_CODE_ATIVACAO_PELO_USUARIO = 3401
AMT_EVENT_CODE_AUTO_ATIVACAO = 3403
AMT_EVENT_CODE_ATIVACAO_VIA_COMPUTADOR_OU_TELEFONE = 3407
AMT_EVENT_CODE_ATIVACAO_POR_UMA_TECLA = 3408
AMT_EVENT_CODE_DESACIONAMENTO_DE_PGM = 3422
AMT_EVENT_CODE_ATIVACAO_PARCIAL = 3456
AMT_EVENT_CODE_KEEP_ALIVE = -2

# AMT_EVENT_MESSAGES = {
#     AMT_EVENT_CODE_EMERGENCIA_MEDICA: AMT_EVENT_EMERGENCIA_MEDICA,
#     AMT_EVENT_CODE_DISPARO_OU_PANICO_DE_INCENDIO: AMT_EVENT_DISPARO_OU_PANICO_DE_INCENDIO,
#     AMT_EVENT_CODE_PANICO_AUDIVEL_OU_SILENCIOSO: AMT_EVENT_PANICO_AUDIVEL_OU_SILENCIOSO,
#     AMT_EVENT_CODE_SENHA_DE_COACAO: AMT_EVENT_SENHA_DE_COACAO,
#     AMT_EVENT_CODE_PANICO_SILENCIOSO: AMT_EVENT_PANICO_SILENCIOSO,
#     AMT_EVENT_CODE_DISPARO_DE_ZONA: AMT_EVENT_DISPARO_DE_ZONA,
#     AMT_EVENT_CODE_DISPARO_DE_CERCA_ELETRICA: AMT_EVENT_DISPARO_DE_CERCA_ELETRICA,
#     AMT_EVENT_CODE_DISPARO_DE_ZONA_24H: AMT_EVENT_DISPARO_DE_ZONA_24H,
#     AMT_EVENT_CODE_TAMPER_DO_TECLADO: AMT_EVENT_TAMPER_DO_TECLADO,
#     AMT_EVENT_CODE_DISPARO_SILENCIOSO: AMT_EVENT_DISPARO_SILENCIOSO,
#     AMT_EVENT_CODE_FALHA_DA_SUPERVISAO_SMART: AMT_EVENT_FALHA_DA_SUPERVISAO_SMART,
#     AMT_EVENT_CODE_SOBRECARGA_NA_SAIDA_AUXILIAR: AMT_EVENT_SOBRECARGA_NA_SAIDA_AUXILIAR,
#     AMT_EVENT_CODE_FALHA_NA_REDE_ELETRICA: AMT_EVENT_FALHA_NA_REDE_ELETRICA,
#     AMT_EVENT_CODE_BATERIA_PRINCIPAL_BAIXA_OU_EM_CURTO_CIRCUITO: AMT_EVENT_BATERIA_PRINCIPAL_BAIXA_OU_EM_CURTO_CIRCUITO,
#     AMT_EVENT_CODE_RESET_PELO_MODO_DE_PROGRAMACAO: AMT_EVENT_RESET_PELO_MODO_DE_PROGRAMACAO,
#     AMT_EVENT_CODE_ALTERACAO_DA_PROGRAMACAO_DO_PAINEL: AMT_EVENT_ALTERACAO_DA_PROGRAMACAO_DO_PAINEL,
#     AMT_EVENT_CODE_BATERIA_PRINCIPAL_AUSENTE_OU_INVERTIDA: AMT_EVENT_BATERIA_PRINCIPAL_AUSENTE_OU_INVERTIDA,
#     AMT_EVENT_CODE_CORTE_OU_CURTO_CIRCUITO_NA_SIRENE: AMT_EVENT_CORTE_OU_CURTO_CIRCUITO_NA_SIRENE,
#     AMT_EVENT_CODE_TOQUE_DE_PORTEIRO: AMT_EVENT_TOQUE_DE_PORTEIRO,
#     AMT_EVENT_CODE_PROBLEMA_EM_TECLADO_OU_RECEPTOR: AMT_EVENT_PROBLEMA_EM_TECLADO_OU_RECEPTOR,
#     AMT_EVENT_CODE_FALHA_NA_LINHA_TELEFONICA: AMT_EVENT_FALHA_NA_LINHA_TELEFONICA,
#     AMT_EVENT_CODE_FALHA_AO_COMUNICAR_EVENTO: AMT_EVENT_FALHA_AO_COMUNICAR_EVENTO,
#     AMT_EVENT_CODE_CORTE_DA_FIACAO_DOS_SENSORES: AMT_EVENT_CORTE_DA_FIACAO_DOS_SENSORES,
#     AMT_EVENT_CODE_CURTO_CIRCUITO_NA_FIACAO_DOS_SENSORES: AMT_EVENT_CURTO_CIRCUITO_NA_FIACAO_DOS_SENSORES,
#     AMT_EVENT_CODE_TAMPER_DO_SENSOR: AMT_EVENT_TAMPER_DO_SENSOR,
#     AMT_EVENT_CODE_BATERIA_BAIXA_DE_SENSOR_SEM_FIO: AMT_EVENT_BATERIA_BAIXA_DE_SENSOR_SEM_FIO,
#     AMT_EVENT_CODE_DESATIVACAO_PELO_USUARIO: AMT_EVENT_DESATIVACAO_PELO_USUARIO,
#     AMT_EVENT_CODE_AUTO_DESATIVACAO: AMT_EVENT_AUTO_DESATIVACAO,
#     AMT_EVENT_CODE_DESATIVACAO_VIA_COMPUTADOR_OU_TELEFONE: AMT_EVENT_DESATIVACAO_VIA_COMPUTADOR_OU_TELEFONE,
#     AMT_EVENT_CODE_ACESSO_REMOTO_PELO_SOFTWARE_DE_DOWNLOAD_UPLOAD: AMT_EVENT_ACESSO_REMOTO_PELO_SOFTWARE_DE_DOWNLOAD_UPLOAD,
#     AMT_EVENT_CODE_FALHA_NO_DOWNLOAD: AMT_EVENT_FALHA_NO_DOWNLOAD,
#     AMT_EVENT_CODE_ACIONAMENTO_DE_PGM: AMT_EVENT_ACIONAMENTO_DE_PGM,
#     AMT_EVENT_CODE_SENHA_INCORRETA: AMT_EVENT_SENHA_INCORRETA,
#     AMT_EVENT_CODE_ANULACAO_TEMPORARIA_DE_ZONA: AMT_EVENT_ANULACAO_TEMPORARIA_DE_ZONA,
#     AMT_EVENT_CODE_ANULACAO_POR_DISPARO: AMT_EVENT_ANULACAO_POR_DISPARO,
#     AMT_EVENT_CODE_TESTE_MANUAL: AMT_EVENT_TESTE_MANUAL,
#     AMT_EVENT_CODE_TESTE_PERIODICO: AMT_EVENT_TESTE_PERIODICO,
#     AMT_EVENT_CODE_SOLICITACAO_DE_MANUTENCAO: AMT_EVENT_SOLICITACAO_DE_MANUTENCAO,
#     AMT_EVENT_CODE_RESET_DO_BUFFER_DE_EVENTOS: AMT_EVENT_RESET_DO_BUFFER_DE_EVENTOS,
#     AMT_EVENT_CODE_LOG_DE_EVENTOS_CHEIO: AMT_EVENT_LOG_DE_EVENTOS_CHEIO,
#     AMT_EVENT_CODE_DATA_E_HORA_FORAM_REINICIADAS: AMT_EVENT_DATA_E_HORA_FORAM_REINICIADAS,
#     AMT_EVENT_CODE_RESTAURACAO_DE_INCENDIO: AMT_EVENT_RESTAURACAO_DE_INCENDIO,
#     AMT_EVENT_CODE_RESTAURACAO_DISPARO_DE_ZONA: AMT_EVENT_RESTAURACAO_DISPARO_DE_ZONA,
#     AMT_EVENT_CODE_RESTAURACAO_DE_DISPARO_DE_CERCA_ELETRICA: AMT_EVENT_RESTAURACAO_DE_DISPARO_DE_CERCA_ELETRICA,
#     AMT_EVENT_CODE_RESTARAUCAO_DISPARO_DE_ZONA_24H: AMT_EVENT_RESTARAUCAO_DISPARO_DE_ZONA_24H,
#     AMT_EVENT_CODE_RESTARAUCAO_TAMPER_DO_TECLADO: AMT_EVENT_RESTARAUCAO_TAMPER_DO_TECLADO,
#     AMT_EVENT_CODE_RESTARAUCAO_DISPARO_SILENCIOSO: AMT_EVENT_RESTARAUCAO_DISPARO_SILENCIOSO,
#     AMT_EVENT_CODE_RESTARAUCAO_DA_SUPERVISAO_SMART: AMT_EVENT_RESTARAUCAO_DA_SUPERVISAO_SMART,
#     AMT_EVENT_CODE_RESTARAUCAO_SOBRECARGA_NA_SAIDA_AUXILIAR: AMT_EVENT_RESTARAUCAO_SOBRECARGA_NA_SAIDA_AUXILIAR,
#     AMT_EVENT_CODE_RESTARAUCAO_FALHA_NA_REDE_ELETRICA: AMT_EVENT_RESTARAUCAO_FALHA_NA_REDE_ELETRICA,
#     AMT_EVENT_CODE_RESTARAUCAO_BAT_PRINC_BAIXA_OU_EM_CURTO_CIRCUITO: AMT_EVENT_RESTARAUCAO_BAT_PRINC_BAIXA_OU_EM_CURTO_CIRCUITO,
#     AMT_EVENT_CODE_RESTARAUCAO_BAT_PRINC_AUSENTE_OU_INVERTIDA: AMT_EVENT_RESTARAUCAO_BAT_PRINC_AUSENTE_OU_INVERTIDA,
#     AMT_EVENT_CODE_RESTARAUCAO_CORTE_OU_CURTO_CIRCUITO_NA_SIRENE: AMT_EVENT_RESTARAUCAO_CORTE_OU_CURTO_CIRCUITO_NA_SIRENE,
#     AMT_EVENT_CODE_RESTARAUCAO_PROBLEMA_EM_TECLADO_OU_RECEPTOR: AMT_EVENT_RESTARAUCAO_PROBLEMA_EM_TECLADO_OU_RECEPTOR,
#     AMT_EVENT_CODE_RESTARAUCAO_LINHA_TELEFONICA: AMT_EVENT_RESTARAUCAO_LINHA_TELEFONICA,
#     AMT_EVENT_CODE_RESTARAUCAO_CORTE_DA_FIACAO_DOS_SENSORES: AMT_EVENT_RESTARAUCAO_CORTE_DA_FIACAO_DOS_SENSORES,
#     AMT_EVENT_CODE_RESTARAUCAO_CURTO_CIRCUITO_NA_FIACAO_DOS_SENSORES: AMT_EVENT_RESTARAUCAO_CURTO_CIRCUITO_NA_FIACAO_DOS_SENSORES,
#     AMT_EVENT_CODE_RESTARAUCAO_TAMPER_DO_SENSOR: AMT_EVENT_RESTARAUCAO_TAMPER_DO_SENSOR,
#     AMT_EVENT_CODE_RESTARAUCAO_BATERIA_BAIXA_DE_SENSOR_SEM_FIO: AMT_EVENT_RESTARAUCAO_BATERIA_BAIXA_DE_SENSOR_SEM_FIO,
#     AMT_EVENT_CODE_ATIVACAO_PELO_USUARIO: AMT_EVENT_ATIVACAO_PELO_USUARIO,
#     AMT_EVENT_CODE_AUTO_ATIVACAO: AMT_EVENT_AUTO_ATIVACAO,
#     AMT_EVENT_CODE_ATIVACAO_VIA_COMPUTADOR_OU_TELEFONE: AMT_EVENT_ATIVACAO_VIA_COMPUTADOR_OU_TELEFONE,
#     AMT_EVENT_CODE_ATIVACAO_POR_UMA_TECLA: AMT_EVENT_ATIVACAO_POR_UMA_TECLA,
#     AMT_EVENT_CODE_DESACIONAMENTO_DE_PGM: AMT_EVENT_DESACIONAMENTO_DE_PGM,
#     AMT_EVENT_CODE_ATIVACAO_PARCIAL: AMT_EVENT_ATIVACAO_PARCIAL,
#     AMT_EVENT_CODE_KEEP_ALIVE: AMT_EVENT_KEEP_ALIVE,
# }

import crcengine

class AMTAlarm:
    """Class that represents the alarm panel"""

    def __init__(
        self, port : int, default_password=None
    ) -> None:
        """Initialize."""

        self.default_password = None
        if default_password is not None:
            self.default_password = str(default_password)
            if len(self.default_password) != 4 and len(self.default_password) != 6:
                raise ValueError

        self.port = port
        self._timeout = 10.0

        self.polling_task = None
        self.reading_task = None
        self.model = None
        self.model_initialized_event = asyncio.Event()
        self.initialized_event = asyncio.Event()

        self.socket: Union[None, socket.socket] = None
        self.client_socket: Union[None, socket.socket] = None
        self.writer: asyncio.StreamWriter = None
        self.reader: asyncio.StreamReader = None
        #self.is_initialized = False
        self.crc = crcengine.create(0xAB, 8, 0, False, False, "", 0)
        self.disarm_crc = crcengine.create(0xAB, 8, 0, False, False, "", 0xFF)
        self.recv_crc = crcengine.create(0x01, 8, 0xFF, False, False, "", 0)

        self.open_sensors: list[Union[None, bool]] = [None] * self.max_sensors
        self.triggered_sensors: list[bool] = [False] * self.max_sensors
        self.bypassed_sensors: list[Union[None, bool]] = [None] * self.max_sensors
        self.partitions: list[Union[None, bool]] = [None] * self.max_partitions
        self.triggered_partitions: list[bool] = [False] * self.max_partitions

        self._listeners = []
        self._mac_address = bytes([])
        self.outstanding_buffer = bytes([])
        self._read_timestamp = 0.0

    async def send_request_model(self):
        await self.send_message(bytes([0xc2]))

    async def send_request_zones(self):
        """Send Request Information packet."""
        print("request zones called")

        if self.default_password is None:
            raise ValueError

        buf = bytes([])
        buf = buf + b"\xe9\x21"

        buf = buf + self.default_password.encode("utf-8")

        cmd = 0x5b

        buf = buf + bytes([cmd]) + b"\x21"

        await self.send_message(buf)

    async def send_arm_partition(self, partition: int):
        """Send Request Information packet."""

        # print("arm partition", partition+1, file=sys.stderr)

        if self.default_password is None:
            raise ValueError

        buf = bytes([])
        buf = buf + b"\x0b\xe9\x21"

        buf = buf + self.default_password.encode("utf-8")

        if len(self.default_password) == 4:
            buf = buf + b"00"

        buf = buf + b"\x41"
        buf = buf + bytes([0x40 + partition + 1])
        buf = buf + b"\x21\x00"
        crc = self.crc(buf)
        buf = buf[0 : len(buf) - 1] + bytes([crc])
        # print("arm partition req buf ", buf, file=sys.stderr)

        try:
            self.writer.write(buf)
            await self.writer.drain()
        except OSError as e:
            self.polling_task = None
            LOGGER.error("Connection error %s", e)
            await self.__accept_new_connection()
        except Exception as e:
            self.polling_task = None
            LOGGER.error("Some unknown error %s", e)
            await self.__accept_new_connection()
            raise

    async def send_disarm_partition(self, partition: int):
        """Send Request Information packet."""

        # print("arm partition", partition+1, file=sys.stderr)

        if self.default_password is None:
            raise ValueError

        buf = bytes([])
        buf = buf + b"\x0b\xe9\x21"

        buf = buf + self.default_password.encode("utf-8")

        if len(self.default_password) == 4:
            buf = buf + b"00"

        buf = buf + b"\x44"
        buf = buf + bytes([0x40 + partition + 1])
        buf = buf + b"\x21\x00"
        crc = self.disarm_crc(buf)
        buf = buf[0 : len(buf) - 1] + bytes([crc])
        # print("disarm partition req buf ", buf, file=sys.stderr)

        try:
            self.writer.write(buf)
            await self.writer.drain()
        except OSError as e:
            self.polling_task = None
            LOGGER.error("Connection error %s", e)
            await self.__accept_new_connection()
        except Exception as e:
            self.polling_task = None
            LOGGER.error("Some unknown error %s", e)
            await self.__accept_new_connection()
            raise

    async def send_test(self):
        """Send Reverse Engineering Test."""

        # unsigned char buffer[] = {0x0b, 0xe9, 0x21, /* senha */ 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, /* fim da senha */ 0x41, 0x40 + partition, 0x21, 0x00};
        # self.t1 = 0x44

        # while True: #if True: if self.default_password is None: raise
        # ValueError

        #     print("send test") buf = bytes([], file=sys.stderr) #buf = buf +
        #     b"\x0b\xe9" + bytes([0x21]) buf = buf + b"\x0a\xe9" +
        #     bytes([0x21])

        #     buf = buf + self.default_password.encode("utf-8") if
        #     len(self.default_password) == 4: buf = buf + b"00"

        #     buf = buf + bytes([self.t1]) #buf = buf + bytes([0x40 + 3+
        #     1]) buf = buf + bytes([0x21]) + b"\x00" self.t1 += 1

        #     crc = self.crc(buf) buf = buf[0 : len(buf) - 1] +
        #     bytes([crc]) print("buf length ", len(buf), file=sys.stderr) print("req buf
        #     ", buf)

        #     self.writer.write(buf) await self.writer.drain() await
        #     asyncio.sleep(1)

        #     print("wrote", file=sys.stderr)

    async def __send_ack(self):
        try:
            self.writer.write(bytes([0xFE]))
            await self.writer.drain()
        except OSError as e:
            self.polling_task = None
            LOGGER.error("Connection error %s", e)
            await self.__accept_new_connection()
        except Exception as e:
            self.polling_task = None
            LOGGER.error("Some unknown error %s", e)
            await self.__accept_new_connection()
            raise

    async def send_raw_message(self, packet: bytes):
        """Send packet."""
        try:
            print("sending ", packet.hex())
            self.writer.write(packet)
            await self.writer.drain()
        except OSError as e:
            self.polling_task = None
            LOGGER.error("Connection error %s", e)
            await self.__accept_new_connection()
        except Exception as e:
            self.polling_task = None
            LOGGER.error("Some unknown error %s", e)
            await self.__accept_new_connection()
            raise

    async def send_message(self, packet: bytes):
        """Send packet."""

        buf = bytes([len(packet)]) + packet
        crc = self.crc(buf + bytes([0]))
        print("crc with ", buf.hex(), hex(crc))
        await self.send_raw_message(buf + bytes([crc]))

    def __handle_amt_event(self, event: int, partition: int, zone: int, client_id):
        if event in (
            AMT_EVENT_CODE_DESATIVACAO_PELO_USUARIO,
            AMT_EVENT_CODE_AUTO_DESATIVACAO,
            AMT_EVENT_CODE_DESATIVACAO_VIA_COMPUTADOR_OU_TELEFONE,
        ):
            # print(
            #     "deactivated, will untrigger too if there is any trigger partition",
            #     partition,
            #     file=sys.stderr,
            # )
            # print("state before", self.partitions)
            if partition == -1:
                self.partitions = [False] * self.max_partitions
                self.triggered_partitions = [False] * self.max_partitions
                self.triggered_sensors = [False] * self.max_sensors
            else:
                self.partitions[partition] = False
                self.triggered_partitions = [False] * self.max_partitions
                self.triggered_sensors = [False] * self.max_sensors
            # print("state after", self.partitions)
        elif event in (
            AMT_EVENT_CODE_ATIVACAO_PELO_USUARIO,
            AMT_EVENT_CODE_AUTO_ATIVACAO,
            AMT_EVENT_CODE_ATIVACAO_VIA_COMPUTADOR_OU_TELEFONE,
            AMT_EVENT_CODE_ATIVACAO_POR_UMA_TECLA,
            AMT_EVENT_CODE_ATIVACAO_PARCIAL,
        ):
            # print("Activated partition (untriggering too)", partition, file=sys.stderr)
            if partition != -1 and zone != -1 and zone < self.max_sensors:
                self.triggered_sensors[zone] = False
            if partition == -1:
                self.triggered_partitions = [False] * self.max_partitions
            else:
                self.triggered_partitions[partition] = False

            # print("state before", self.partitions)
            if partition == -1:
                self.partitions = [True] * self.max_partitions
            else:
                self.partitions[partition] = True
            # print("state after", self.partitions)
        if event == AMT_EVENT_CODE_FALHA_AO_COMUNICAR_EVENTO:
            #LOGGER.error("Alarm panel error: %s", AMT_EVENT_MESSAGES[event])
            print("Alarm panel error AMT_EVENT_CODE_FALHA_AO_COMUNICAR_EVENTO")
        if event in (
            AMT_EVENT_CODE_EMERGENCIA_MEDICA,
            AMT_EVENT_CODE_DISPARO_OU_PANICO_DE_INCENDIO,
            AMT_EVENT_CODE_PANICO_AUDIVEL_OU_SILENCIOSO,
            AMT_EVENT_CODE_SENHA_DE_COACAO,
            AMT_EVENT_CODE_PANICO_SILENCIOSO,
            AMT_EVENT_CODE_DISPARO_DE_ZONA,
            AMT_EVENT_CODE_DISPARO_DE_CERCA_ELETRICA,
            AMT_EVENT_CODE_DISPARO_DE_ZONA_24H,
            AMT_EVENT_CODE_TAMPER_DO_TECLADO,
            AMT_EVENT_CODE_DISPARO_SILENCIOSO,
            AMT_EVENT_CODE_CORTE_OU_CURTO_CIRCUITO_NA_SIRENE,
            AMT_EVENT_CODE_PROBLEMA_EM_TECLADO_OU_RECEPTOR,
            AMT_EVENT_CODE_FALHA_NA_LINHA_TELEFONICA,
            AMT_EVENT_CODE_CORTE_DA_FIACAO_DOS_SENSORES,
            AMT_EVENT_CODE_CURTO_CIRCUITO_NA_FIACAO_DOS_SENSORES,
            AMT_EVENT_CODE_TAMPER_DO_SENSOR,
        ):
            # print("Triggering partition ", partition, file=sys.stderr)
            # LOGGER.error(
            #     "Triggering partition %d with error: %s",
            #     partition,
            #     AMT_EVENT_MESSAGES[event],
            # )
            if partition != -1 and zone != -1 and zone < self.max_sensors:
                self.triggered_sensors[zone] = True
            if partition == -1:
                self.triggered_partitions = [True] * self.max_partitions
            else:
                self.triggered_partitions[partition] = True
        if event in (
            AMT_EVENT_CODE_RESTAURACAO_DE_INCENDIO,
            AMT_EVENT_CODE_RESTAURACAO_DISPARO_DE_ZONA,
            AMT_EVENT_CODE_RESTAURACAO_DE_DISPARO_DE_CERCA_ELETRICA,
            AMT_EVENT_CODE_RESTARAUCAO_DISPARO_DE_ZONA_24H,
            AMT_EVENT_CODE_RESTARAUCAO_TAMPER_DO_TECLADO,
            AMT_EVENT_CODE_RESTARAUCAO_DISPARO_SILENCIOSO,
            AMT_EVENT_CODE_RESTARAUCAO_DA_SUPERVISAO_SMART,
            AMT_EVENT_CODE_RESTARAUCAO_SOBRECARGA_NA_SAIDA_AUXILIAR,
            AMT_EVENT_CODE_RESTARAUCAO_FALHA_NA_REDE_ELETRICA,
            AMT_EVENT_CODE_RESTARAUCAO_BAT_PRINC_BAIXA_OU_EM_CURTO_CIRCUITO,
            AMT_EVENT_CODE_RESTARAUCAO_BAT_PRINC_AUSENTE_OU_INVERTIDA,
            AMT_EVENT_CODE_RESTARAUCAO_CORTE_OU_CURTO_CIRCUITO_NA_SIRENE,
            AMT_EVENT_CODE_RESTARAUCAO_PROBLEMA_EM_TECLADO_OU_RECEPTOR,
            AMT_EVENT_CODE_RESTARAUCAO_LINHA_TELEFONICA,
            AMT_EVENT_CODE_RESTARAUCAO_CORTE_DA_FIACAO_DOS_SENSORES,
            AMT_EVENT_CODE_RESTARAUCAO_CURTO_CIRCUITO_NA_FIACAO_DOS_SENSORES,
            AMT_EVENT_CODE_RESTARAUCAO_TAMPER_DO_SENSOR,
            AMT_EVENT_CODE_RESTARAUCAO_BATERIA_BAIXA_DE_SENSOR_SEM_FIO,
        ):
            # print("UN Triggering partition ", partition, file=sys.stderr)
            if partition != -1 and zone != -1 and zone < self.max_sensors:
                self.triggered_sensors[zone] = False
            if partition == -1:
                self.triggered_partitions = [False] * self.max_partitions
            else:
                self.triggered_partitions[partition] = False
        self.__call_listeners()

    async def __handle_packet(self, packet: bytes):
        LOGGER.debug ('received packet packet', packet.hex(), file=sys.stderr)
        if len(packet) > 0:
            cmd = packet[0]
            if cmd == AMT_REQ_CODE_MODELO and len(packet) > 1:
                # no ack because it is a response
                print("cmd 0xc2: ", packet.hex(), file=sys.stderr)
                self.model = (packet[1:]).decode("utf-8")
                self.model_initialized_event.set()
                print("Model is ", self.model)
            elif cmd == AMT_COMMAND_CODE_HEARTBEAT and len(packet) == 1:
                print("cmd 0xf7: ", packet.hex(), file=sys.stderr)
                await self.__send_ack()
            # elif cmd == 0x94:
            elif cmd == AMT_COMMAND_CODE_CONECTAR:
                print("cmd 0x94: ", packet.hex(), file=sys.stderr)
                if len(self._mac_address) == 0:
                    self._mac_address = packet[4:7]

                self.initialized_event.set()
                await self.__send_ack()
                await self.send_request_model()
            # elif cmd == 0xC4:
            elif cmd == AMT_REQ_CODE_MAC and len(packet) == 7:
                print("cmd 0xc4: ", packet.hex(), file=sys.stderr)
                self._mac_address = packet[1:7]
            # elif cmd == 0xB0 and len(packet) == 17 and packet[1] == 0x12:
            elif (
                    cmd == AMT_COMMAND_CODE_EVENT_CONTACT_ID # 0xb0
                    and len(packet) == 17
                    and packet[1] == 0x12 or packet[0] == 0x11
            ):
                print("cmd 0xb0: ", packet.hex(), file=sys.stderr)
                # def unescape_zero(i):
                #     return i if i != 0xA else 0

                # client_id = (
                #     unescape_zero(packet[2]) * 1000
                #     + unescape_zero(packet[3]) * 100
                #     + unescape_zero(packet[4]) * 10
                #     + unescape_zero(packet[5])
                # )
                client_id = _bcd_to_decimal(packet[2:6])
                # ev_id = (
                #     unescape_zero(packet[8]) * 1000
                #     + unescape_zero(packet[9]) * 100
                #     + unescape_zero(packet[10]) * 10
                #     + unescape_zero(packet[11])
                # )
                ev_id = _bcd_to_decimal(packet[8:12])
                # partition = unescape_zero(packet[12]) * 10 + unescape_zero(packet[13]) - 1
                partition = _bcd_to_decimal(packet[12:14]) - 1
                # zone = (
                #     unescape_zero(packet[14]) * 100
                #     + unescape_zero(packet[15]) * 10
                #     + unescape_zero(packet[16])
                # )
                zone = _bcd_to_decimal(packet[14:17])

                print(
                    "event",
                    ev_id,
                    "from partition",
                    partition,
                    "and zone",
                    zone,
                    file=sys.stderr,
                )
                self.__handle_amt_event(ev_id, partition, zone, client_id)

                await self.__send_ack()
            elif (
                    cmd == AMT_COMMAND_CODE_EVENT_DATA_HORA
                    and len(packet) == 29
                    and packet[1] == 0x12
            ):
                pass
            elif cmd == AMT_COMMAND_CODE_SOLICITA_DATA_HORA:
                print("handling time command")
                timezone = packet[1] if len(packet) > 1 else 0
                now = time.time()
                (
                    tm_year,
                    tm_mon,
                    tm_mday,
                    tm_hour,
                    tm_min,
                    tm_sec,
                    tm_wday,
                    _,
                    _,
                ) = time.gmtime(now - timezone * 3600)
                tm_year -= 2000
                tm_wday = (tm_wday + 1) % 7 + 1
                
                response = bytes([cmd]) + bytes(
                    map(
                        _decimal_to_bcd_nibble,
                        [tm_year, tm_mon, tm_mday, tm_wday, tm_hour, tm_min, tm_sec],
                    )
                )
                await self.send_message(response)

            # elif (
            #     cmd == 0xE9
            #     and len(packet) == 2
            #     and (packet[1] == 0xE5 or packet[1] == 0xFE)
            # ):
            elif cmd == AMT_PROTOCOL_ISEC_MOBILE and len(packet) == 2:
                if packet[1] == 0xFE:
                    await self.__send_ack()
                else:
                    # print("cmd 0xe9: ", packet, file=sys.stderr)
                    if packet[1] == 0xE1:
                        print("We are using wrong password in AMT integration?")
                    elif packet[1] == 0xE2:
                        pass
                    elif packet[2] == 0xE5:
                        print("Some error")
                    else:
                        print("Some error")
                    await self.__send_ack()
            elif (
                    cmd == AMT_PROTOCOL_ISEC_MOBILE
                    and len(packet) == 2
            ):
                print("cmd 0xe9 error: ", packet.hex(), file=sys.stderr)
                #LOGGER.error("We are using wrong password in AMT integration?")
                await self.__send_ack()
                # elif cmd == 0xE9 and len(packet) >= 3 * 8:
            elif cmd == AMT_PROTOCOL_ISEC_MOBILE and len(packet) >= 3 * 8:
                print("e9 update all partitions and zones", file=sys.stderr)
                for x in range(6):
                    for i in range(8):
                        c = packet[x + 1]
                        self.open_sensors[x * 8 + i] = ((c >> i) & 1) == 1

                    for i in range(8):
                        c = packet[x + 1 + 8]
                        self.triggered_sensors[x * 8 + i] = ((c >> i) & 1) == 1

                    for i in range(8):
                        c = packet[x + 1 + 16]
                        self.bypassed_sensors[x * 8 + i] = ((c >> i) & 1) == 1

                    c = packet[1 + 8 + 8 + 8 + 3]
                    for i in range(2):
                        self.partitions[i] = bool((c >> i) & 1)

                    c = packet[1 + 8 + 8 + 8 + 3 + 1]
                    for i in range(2):
                        self.partitions[i + 2] = bool((c >> i) & 1)


                c = packet[30]
                self.siren_activated = bool((c >> 1) & 1)
                self.zones_triggered = bool((c >> 2) & 1)
                self.panel_activated = bool((c >> 3) & 1)
                self.problem_detected = bool((c >> 0) & 1)

                c = packet[36]
                self.overload_aux = bool((c >> 4) & 1)
                self.battery_short_circuit = bool((c >> 3) & 1)
                self.battery_not_found = bool((c >> 2) & 1)
                self.battery_low = bool((c >> 1) & 1)
                self.power_out = bool((c >> 0) & 1)

                #print("siren", self.siren_activated, "zone triggered", self.zones_triggered, "panel activated", self.panel_activated, "problem_detected", self.problem_detected)
                #print("overload aux", self.overload_aux, "battery_short_circuit", self.battery_short_circuit, "battery_not_found", self.battery_not_found, "battery_low", self.battery_low, "power_out", self.power_out)

                c = packet[43]
                self.error_communicating_event = bool((c >> 3) & 1)
                self.error_telephone_line = bool((c >> 2) & 1)
                self.error_siren_short_circuit = bool((c >> 1) & 1)
                self.error_siren_cut = bool((c >> 0) & 1)

                #print("(error) communication event", self.error_communicating_event, "telephone line", self.error_telephone_line, "siren_short_circuit", self.error_siren_short_circuit, "siren cut", self.error_siren_cut)

                self.__call_listeners()
            else:
                print("AMT doesn't know how to deal with %s ?", packet.hex())

    async def __handle_data(self):
        while len(self.outstanding_buffer) != 0:
            is_nope = self.outstanding_buffer[0] == 0xF7
            packet_size = 1 if is_nope else self.outstanding_buffer[0]
            packet_start = 1 if not is_nope else 0

            if (
                not is_nope
                and len(self.outstanding_buffer) < packet_size + 1
                or self.outstanding_buffer[0] == 0
            ):
                break

            crc = packet_start  # crc_size is 1 if not is_nope and 0 if is_nope, just as packet_start
            buf = self.outstanding_buffer[: packet_size + packet_start + crc]
            self.outstanding_buffer = self.outstanding_buffer[
                packet_start + packet_size + crc :
            ]

            assert len(buf) == packet_start + packet_size + crc
            if crc:
                if self.recv_crc(buf) != 0:
                    print(
                        "Buffer %s doesn't match CRC, which should be %d but actually was %d",
                        buf,
                        self.recv_crc(buf),
                        buf[-1],
                    )
                    # Drop one byte and try synchronization again
                    self.outstanding_buffer = buf[1:] + self.outstanding_buffer
                    continue

            if len(buf) != 0:
                await self.__handle_packet(buf[packet_start:-crc])

    async def __handle_polling(self):
        """Handle read data from alarm."""

        print("handle_polling")

        if self.default_password is None:
            return

        print("there is a default_password")
        while True:
            try:
                await self.send_request_zones()
                await asyncio.sleep(1)

                if (
                    self._read_timestamp is not None
                    and time.monotonic() - self._read_timestamp >= self._timeout
                ):
                    self.polling_task = None
                    print("Timeout error", (time.monotonic() - self._read_timestamp))
                    await self.__accept_new_connection()
                    return

            except OSError as ex:
                self.polling_task = None
                print("Connection error %s", ex)
                await self.__accept_new_connection()
                return
            except Exception as ex:
                self.polling_task = None
                print("Some unknown error %s", ex)
                await self.__accept_new_connection()
                raise

    async def __handle_read_from_stream(self):
        """Handle read data from alarm."""

        while True:
            self._read_timestamp = time.monotonic()
            data = await self.reader.read(4096)
            if self.reader.at_eof():
                self.reading_task = None
                print("Connection dropped by other side")
                await self.__accept_new_connection()
                return

            self.outstanding_buffer += data

            try:
                await self.__handle_data()
            except Exception as ex:
                print("Some unknown error %s", ex)
                await self.__accept_new_connection()
                raise

    async def unique(self) -> str:
        await self.model_initialized_event.wait()
        return self.model + ' ' + self._mac_address.hex()

    async def wait_connection(self) -> bool:
        """Test if we can authenticate with the host."""

        print(
            "Not connected to Alarm Panel. Waiting connection from Alarm Panel"
        )
        # print("Logged error", file=sys.stderr)
        # traceback.print_stack(file=sys.stderr)

        self.outstanding_buffer = bytes([])
        self.initialized_event.clear()
        self.model_initialized_event.clear()

        self.open_sensors: list[Union[None, bool]] = [None] * self.max_sensors
        self.partitions: list[Union[None, bool]] = [None] * self.max_partitions
        self.triggered_partitions = [False] * self.max_partitions
        self.triggered_sensors = [False] * self.max_sensors

        self.close()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.socket.setblocking(False)
        self.socket.bind(("", self.port))
        self.socket.listen(1)

        # print ("Will call call_listeners", file=sys.stderr)
        self.__call_listeners()
        # print ("Called call_listeners", file=sys.stderr)

        loop = asyncio.get_running_loop()
        while True:
            try:
                (self.client_socket, _) = await asyncio.wait_for(
                    loop.sock_accept(self.socket), timeout=600
                )
                print("Connection accepted")
            except asyncio.TimeoutError:
                print(
                    "Timeout waiting on connection from Alarm Panel (60s). Retrying"
                )
                continue
            try:
                (self.reader, self.writer) = await asyncio.open_connection(
                    None, sock=self.client_socket
                )
            except asyncio.TimeoutError:
                print(
                    "Timeout opening connection from Alarm Panel (60s). Retrying"
                )
                continue
            # print("Connection from Alarm Panel established", file=sys.stderr)
            self.__call_listeners()
            break

        return True

    async def async_alarm_disarm(self, code=None):
        """Send disarm command."""

    async def async_alarm_arm_night(self, code=None):
        """Send disarm command."""
        for i in range(self.max_partitions):
            if CONF_NIGHT_PARTITION_LIST[i] in self.config_entry.data:
                if self.config_entry.data[CONF_NIGHT_PARTITION_LIST[i]]:
                    await self.send_arm_partition(i)
            else:
                await self.send_arm_partition(i)

    async def async_alarm_arm_away(self, code=None):
        """Send disarm command."""
        if self.config_entry.data[CONF_AWAY_MODE_ENABLED]:
            for i in range(self.max_partitions):
                if CONF_AWAY_PARTITION_LIST[i] in self.config_entry.data:
                    if self.config_entry.data[CONF_AWAY_PARTITION_LIST[i]]:
                        self.send_arm_partition(i)
                else:
                    self.send_arm_partition(i)

    async def async_alarm_arm_home(self, code=None):
        """Send disarm command."""
        if self.config_entry.data[CONF_HOME_MODE_ENABLED]:
            for i in range(self.max_partitions):
                if CONF_HOME_PARTITION_LIST[i] in self.config_entry.data:
                    if self.config_entry.data[CONF_HOME_PARTITION_LIST[i]]:
                        await self.send_arm_partition(i)
                else:
                    await self.send_arm_partition(i)

    def close(self):
        """Close and free resources."""
        if self.socket is not None:
            self.socket.close()
        if self.client_socket is not None:
            self.client_socket.close()
        if self.writer is not None:
            self.writer.close()

    async def async_update(self):
        """Asynchronously update hub state."""
        print("async_update")

        if self.polling_task is None:
            self.polling_task = asyncio.create_task(self.__handle_polling())
        if self.reading_task is None:
            self.reading_task = asyncio.create_task(self.__handle_read_from_stream())

        print("tasks created")

        await self.initialized_event.wait()
        await self.model_initialized_event.wait()

    async def wait_connection_and_update(self):
        """Call asynchronously wait_connection and then after a update."""
        print("waiting connection")
        await self.wait_connection()
        print("connected, i think")
        await self.async_update()

    async def __accept_new_connection(self):
        self._read_timestamp = None
        if self.polling_task is not None:
            self.polling_task.cancel()
            self.polling_task = None
        if self.reading_task is not None:
            self.reading_task.cancel()
            self.reading_task = None
        if self.client_socket is not None:
            self.client_socket.close()

        asyncio.create_task(self.wait_connection_and_update())

    def get_partitions(self):
        """Return partitions array."""
        return self.partitions

    def get_triggered_partitions(self):
        """Return partitions array."""
        return self.triggered_partitions

    def get_open_sensors(self):
        """Return motion sensors states."""
        return self.open_sensors

    def listen_event(self, listener):
        """Add object as listener."""
        if listener not in self._listeners:
            self._listeners.append(listener)

    def remove_listen_event(self, listener):
        """Add object as listener."""
        if listener in self._listeners:
            self._listeners.remove(listener)

    def __call_listeners(self):
        """Call all listeners."""
        print ("__call_listeners: ", len(self._listeners), file=sys.stderr)
        for i in self._listeners:
            i.alarm_update()

    @property
    def max_sensors(self):
        """Return the maximum number of sensors the platform may have."""
        return 48

    def is_sensor_configured(self, index):
        """Check if the numbered sensor is configured."""
        return True

    @property
    def max_partitions(self):
        """Return the maximum number of partitions the platform may have."""
        return 4

    def is_partition_configured(self, index):
        """Check if the numbered partition is configured."""
        return True

async def main():
    alarm = AMTAlarm(9009, 581000)

    await alarm.wait_connection_and_update()
    await asyncio.sleep(5)
    
if __name__ == "__main__":
    asyncio.run(main())
