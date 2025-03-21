import asyncio
import socket
import time
from typing import Union
import sys
import logging

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
AMT_PROTOCOL_ISECPROGRAM = 0xE7
# Byte 1 - 0x21 (start of frame)
# Byte 2 to 5 or 2 to 7 - password
# Byte 6 or 8 - command
# Byte 7 or 9 to ... - content
# Byte ... + 1 - 0x21 (end of frame)

AMT_ISEC_MOBILE_COMMAND_CODE_COMAND_ACCEPTED = 0xFE
AMT_ISEC_MOBILE_COMMAND_CODE_INVALID_PASSWORD = 0xE1
AMT_ISEC_MOBILE_COMMAND_CODE_INVALID_COMMAND = 0xE2
AMT_ISEC_MOBILE_COMMAND_CODE_NOT_PARTITIONED = 0xE3
AMT_ISEC_MOBILE_COMMAND_CODE_OPEN_ZONES = 0xE4
AMT_ISEC_MOBILE_COMMAND_CODE_DEPRECATED_COMMAND = 0xE5
AMT_ISEC_MOBILE_COMMAND_CODE_NO_PERMISSION_BY_PASS = 0xE6
AMT_ISEC_MOBILE_COMMAND_CODE_NO_PERMISSION = 0xE7
AMT_ISEC_MOBILE_COMMAND_CODE_ARMED = 0xE8
AMT_ISEC_MOBILE_COMMAND_CODE_NO_ZONES = 0xEA


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

AMT_EVENT_EMERGENCIA_MEDICA = "Emergência Médica"
AMT_EVENT_DISPARO_OU_PANICO_DE_INCENDIO = "Disparo ou pânico de incêndio"
AMT_EVENT_PANICO_AUDIVEL_OU_SILENCIOSO = "Pânico audível ou silencioso"
AMT_EVENT_SENHA_DE_COACAO = "Senha de coação"
AMT_EVENT_PANICO_SILENCIOSO = "Pânico silencioso"
AMT_EVENT_DISPARO_DE_ZONA = "Disparo de zona"
AMT_EVENT_DISPARO_DE_CERCA_ELETRICA = "Disparo de cerca elétrica"
AMT_EVENT_DISPARO_DE_ZONA_24H = "Disparo de zona 24h"
AMT_EVENT_TAMPER_DO_TECLADO = "Tamper do teclado"
AMT_EVENT_DISPARO_SILENCIOSO = "Disparo silencioso"
AMT_EVENT_FALHA_DA_SUPERVISAO_SMART = "Falha da supervisão Smart"
AMT_EVENT_SOBRECARGA_NA_SAIDA_AUXILIAR = "Sobrecarga na saída auxiliary"
AMT_EVENT_FALHA_NA_REDE_ELETRICA = "Falha na rede elétrica"
AMT_EVENT_BATERIA_PRINCIPAL_BAIXA_OU_EM_CURTO_CIRCUITO = (
    "Bateria principal baixa ou em curto-circuito"
)
AMT_EVENT_RESET_PELO_MODO_DE_PROGRAMACAO = "Reset pelo modo de programação"
AMT_EVENT_ALTERACAO_DA_PROGRAMACAO_DO_PAINEL = "Alteração da programação do painel"
AMT_EVENT_BATERIA_PRINCIPAL_AUSENTE_OU_INVERTIDA = (
    "Bateria principal ausente ou invertida"
)
AMT_EVENT_CORTE_OU_CURTO_CIRCUITO_NA_SIRENE = "Corte ou curto-circuito na sirene"
AMT_EVENT_TOQUE_DE_PORTEIRO = "Toque de porteiro"
AMT_EVENT_PROBLEMA_EM_TECLADO_OU_RECEPTOR = "Problema em teclado ou receptor"
AMT_EVENT_FALHA_NA_LINHA_TELEFONICA = "Falha na linha telefônica"
AMT_EVENT_FALHA_AO_COMUNICAR_EVENTO = "Falha ao comunicar evento"
AMT_EVENT_CORTE_DA_FIACAO_DOS_SENSORES = "Corte da fiação dos sensores"
AMT_EVENT_CURTO_CIRCUITO_NA_FIACAO_DOS_SENSORES = (
    "Curto-circuito na fiação dos sensores"
)
AMT_EVENT_TAMPER_DO_SENSOR = "Tamper do sensor"
AMT_EVENT_BATERIA_BAIXA_DE_SENSOR_SEM_FIO = "Bateria baixa de sensor sem fio"
AMT_EVENT_DESATIVACAO_PELO_USUARIO = "Desativação pelo usuário"
AMT_EVENT_AUTO_DESATIVACAO = "Auto-desativação"
AMT_EVENT_DESATIVACAO_VIA_COMPUTADOR_OU_TELEFONE = (
    "Desativação via computador ou telefone"
)
AMT_EVENT_ACESSO_REMOTO_PELO_SOFTWARE_DE_DOWNLOAD_UPLOAD = (
    "Acesso remoto pelo software de download/upload"
)
AMT_EVENT_FALHA_NO_DOWNLOAD = "Falha no download"
AMT_EVENT_ACIONAMENTO_DE_PGM = "Acionamento de PGM"
AMT_EVENT_SENHA_INCORRETA = "Senha incorreta"
AMT_EVENT_ANULACAO_TEMPORARIA_DE_ZONA = "Anulação temporária de zona"
AMT_EVENT_ANULACAO_POR_DISPARO = "Anulação por disparo"
AMT_EVENT_TESTE_MANUAL = "Teste manual"
AMT_EVENT_TESTE_PERIODICO = "Teste periódico"
AMT_EVENT_SOLICITACAO_DE_MANUTENCAO = "Solicitação de manutenção"
AMT_EVENT_RESET_DO_BUFFER_DE_EVENTOS = "Reset do buffer de eventos"
AMT_EVENT_LOG_DE_EVENTOS_CHEIO = "Log de eventos cheio"
AMT_EVENT_DATA_E_HORA_FORAM_REINICIADAS = "Data e hora foram reiniciadas"
AMT_EVENT_RESTAURACAO_DE_INCENDIO = "Restauração de incêndio"
AMT_EVENT_RESTAURACAO_DISPARO_DE_ZONA = "Restauração disparo de zona"
AMT_EVENT_RESTAURACAO_DE_DISPARO_DE_CERCA_ELETRICA = (
    "Restauração de disparo de cerca elétrica"
)
AMT_EVENT_RESTARAUCAO_DISPARO_DE_ZONA_24H = "Restauração disparo de zona 24h"
AMT_EVENT_RESTARAUCAO_TAMPER_DO_TECLADO = "Restauração tamper do teclado"
AMT_EVENT_RESTARAUCAO_DISPARO_SILENCIOSO = "Restauração disparo silencioso"
AMT_EVENT_RESTARAUCAO_DA_SUPERVISAO_SMART = "Restauração da supervisão Smart"
AMT_EVENT_RESTARAUCAO_SOBRECARGA_NA_SAIDA_AUXILIAR = (
    "Restauração sobrecarga na saída auxiliary"
)
AMT_EVENT_RESTARAUCAO_FALHA_NA_REDE_ELETRICA = "Restauração falha na rede elétrica"
AMT_EVENT_RESTARAUCAO_BAT_PRINC_BAIXA_OU_EM_CURTO_CIRCUITO = (
    "Restauração bat. princ. baixa ou em curto-circuito"
)
AMT_EVENT_RESTARAUCAO_BAT_PRINC_AUSENTE_OU_INVERTIDA = (
    "Restauração bat. princ. ausente ou invertida"
)
AMT_EVENT_RESTARAUCAO_CORTE_OU_CURTO_CIRCUITO_NA_SIRENE = (
    "Restauração corte ou curto-circuito na sirene"
)
AMT_EVENT_RESTARAUCAO_PROBLEMA_EM_TECLADO_OU_RECEPTOR = (
    "Restauração problema em teclado ou receptor"
)
AMT_EVENT_RESTARAUCAO_LINHA_TELEFONICA = "Restauração linha telefônica"
AMT_EVENT_RESTARAUCAO_CORTE_DA_FIACAO_DOS_SENSORES = (
    "Restauração corte da fiação dos sensores"
)
AMT_EVENT_RESTARAUCAO_CURTO_CIRCUITO_NA_FIACAO_DOS_SENSORES = (
    "Restauração curto-circuito na fiação dos sensores"
)
AMT_EVENT_RESTARAUCAO_TAMPER_DO_SENSOR = "Restauração tamper do sensor"
AMT_EVENT_RESTARAUCAO_BATERIA_BAIXA_DE_SENSOR_SEM_FIO = (
    "Restauração bateria baixa de sensor sem fio"
)
AMT_EVENT_ATIVACAO_PELO_USUARIO = "Ativação pelo usuário"
AMT_EVENT_AUTO_ATIVACAO = "Auto-ativação"
AMT_EVENT_ATIVACAO_VIA_COMPUTADOR_OU_TELEFONE = "Ativação via computador ou telefone"
AMT_EVENT_ATIVACAO_POR_UMA_TECLA = "Ativação por uma tecla"
AMT_EVENT_DESACIONAMENTO_DE_PGM = "Desacionamento de PGM"
AMT_EVENT_ATIVACAO_PARCIAL = "Ativação parcial"
AMT_EVENT_KEEP_ALIVE = "Keep-Alive"

AMT_EVENT_MESSAGES = {
    AMT_EVENT_CODE_EMERGENCIA_MEDICA: AMT_EVENT_EMERGENCIA_MEDICA,
    AMT_EVENT_CODE_DISPARO_OU_PANICO_DE_INCENDIO: AMT_EVENT_DISPARO_OU_PANICO_DE_INCENDIO,
    AMT_EVENT_CODE_PANICO_AUDIVEL_OU_SILENCIOSO: AMT_EVENT_PANICO_AUDIVEL_OU_SILENCIOSO,
    AMT_EVENT_CODE_SENHA_DE_COACAO: AMT_EVENT_SENHA_DE_COACAO,
    AMT_EVENT_CODE_PANICO_SILENCIOSO: AMT_EVENT_PANICO_SILENCIOSO,
    AMT_EVENT_CODE_DISPARO_DE_ZONA: AMT_EVENT_DISPARO_DE_ZONA,
    AMT_EVENT_CODE_DISPARO_DE_CERCA_ELETRICA: AMT_EVENT_DISPARO_DE_CERCA_ELETRICA,
    AMT_EVENT_CODE_DISPARO_DE_ZONA_24H: AMT_EVENT_DISPARO_DE_ZONA_24H,
    AMT_EVENT_CODE_TAMPER_DO_TECLADO: AMT_EVENT_TAMPER_DO_TECLADO,
    AMT_EVENT_CODE_DISPARO_SILENCIOSO: AMT_EVENT_DISPARO_SILENCIOSO,
    AMT_EVENT_CODE_FALHA_DA_SUPERVISAO_SMART: AMT_EVENT_FALHA_DA_SUPERVISAO_SMART,
    AMT_EVENT_CODE_SOBRECARGA_NA_SAIDA_AUXILIAR: AMT_EVENT_SOBRECARGA_NA_SAIDA_AUXILIAR,
    AMT_EVENT_CODE_FALHA_NA_REDE_ELETRICA: AMT_EVENT_FALHA_NA_REDE_ELETRICA,
    AMT_EVENT_CODE_BATERIA_PRINCIPAL_BAIXA_OU_EM_CURTO_CIRCUITO: AMT_EVENT_BATERIA_PRINCIPAL_BAIXA_OU_EM_CURTO_CIRCUITO,
    AMT_EVENT_CODE_RESET_PELO_MODO_DE_PROGRAMACAO: AMT_EVENT_RESET_PELO_MODO_DE_PROGRAMACAO,
    AMT_EVENT_CODE_ALTERACAO_DA_PROGRAMACAO_DO_PAINEL: AMT_EVENT_ALTERACAO_DA_PROGRAMACAO_DO_PAINEL,
    AMT_EVENT_CODE_BATERIA_PRINCIPAL_AUSENTE_OU_INVERTIDA: AMT_EVENT_BATERIA_PRINCIPAL_AUSENTE_OU_INVERTIDA,
    AMT_EVENT_CODE_CORTE_OU_CURTO_CIRCUITO_NA_SIRENE: AMT_EVENT_CORTE_OU_CURTO_CIRCUITO_NA_SIRENE,
    AMT_EVENT_CODE_TOQUE_DE_PORTEIRO: AMT_EVENT_TOQUE_DE_PORTEIRO,
    AMT_EVENT_CODE_PROBLEMA_EM_TECLADO_OU_RECEPTOR: AMT_EVENT_PROBLEMA_EM_TECLADO_OU_RECEPTOR,
    AMT_EVENT_CODE_FALHA_NA_LINHA_TELEFONICA: AMT_EVENT_FALHA_NA_LINHA_TELEFONICA,
    AMT_EVENT_CODE_FALHA_AO_COMUNICAR_EVENTO: AMT_EVENT_FALHA_AO_COMUNICAR_EVENTO,
    AMT_EVENT_CODE_CORTE_DA_FIACAO_DOS_SENSORES: AMT_EVENT_CORTE_DA_FIACAO_DOS_SENSORES,
    AMT_EVENT_CODE_CURTO_CIRCUITO_NA_FIACAO_DOS_SENSORES: AMT_EVENT_CURTO_CIRCUITO_NA_FIACAO_DOS_SENSORES,
    AMT_EVENT_CODE_TAMPER_DO_SENSOR: AMT_EVENT_TAMPER_DO_SENSOR,
    AMT_EVENT_CODE_BATERIA_BAIXA_DE_SENSOR_SEM_FIO: AMT_EVENT_BATERIA_BAIXA_DE_SENSOR_SEM_FIO,
    AMT_EVENT_CODE_DESATIVACAO_PELO_USUARIO: AMT_EVENT_DESATIVACAO_PELO_USUARIO,
    AMT_EVENT_CODE_AUTO_DESATIVACAO: AMT_EVENT_AUTO_DESATIVACAO,
    AMT_EVENT_CODE_DESATIVACAO_VIA_COMPUTADOR_OU_TELEFONE: AMT_EVENT_DESATIVACAO_VIA_COMPUTADOR_OU_TELEFONE,
    AMT_EVENT_CODE_ACESSO_REMOTO_PELO_SOFTWARE_DE_DOWNLOAD_UPLOAD: AMT_EVENT_ACESSO_REMOTO_PELO_SOFTWARE_DE_DOWNLOAD_UPLOAD,
    AMT_EVENT_CODE_FALHA_NO_DOWNLOAD: AMT_EVENT_FALHA_NO_DOWNLOAD,
    AMT_EVENT_CODE_ACIONAMENTO_DE_PGM: AMT_EVENT_ACIONAMENTO_DE_PGM,
    AMT_EVENT_CODE_SENHA_INCORRETA: AMT_EVENT_SENHA_INCORRETA,
    AMT_EVENT_CODE_ANULACAO_TEMPORARIA_DE_ZONA: AMT_EVENT_ANULACAO_TEMPORARIA_DE_ZONA,
    AMT_EVENT_CODE_ANULACAO_POR_DISPARO: AMT_EVENT_ANULACAO_POR_DISPARO,
    AMT_EVENT_CODE_TESTE_MANUAL: AMT_EVENT_TESTE_MANUAL,
    AMT_EVENT_CODE_TESTE_PERIODICO: AMT_EVENT_TESTE_PERIODICO,
    AMT_EVENT_CODE_SOLICITACAO_DE_MANUTENCAO: AMT_EVENT_SOLICITACAO_DE_MANUTENCAO,
    AMT_EVENT_CODE_RESET_DO_BUFFER_DE_EVENTOS: AMT_EVENT_RESET_DO_BUFFER_DE_EVENTOS,
    AMT_EVENT_CODE_LOG_DE_EVENTOS_CHEIO: AMT_EVENT_LOG_DE_EVENTOS_CHEIO,
    AMT_EVENT_CODE_DATA_E_HORA_FORAM_REINICIADAS: AMT_EVENT_DATA_E_HORA_FORAM_REINICIADAS,
    AMT_EVENT_CODE_RESTAURACAO_DE_INCENDIO: AMT_EVENT_RESTAURACAO_DE_INCENDIO,
    AMT_EVENT_CODE_RESTAURACAO_DISPARO_DE_ZONA: AMT_EVENT_RESTAURACAO_DISPARO_DE_ZONA,
    AMT_EVENT_CODE_RESTAURACAO_DE_DISPARO_DE_CERCA_ELETRICA: AMT_EVENT_RESTAURACAO_DE_DISPARO_DE_CERCA_ELETRICA,
    AMT_EVENT_CODE_RESTARAUCAO_DISPARO_DE_ZONA_24H: AMT_EVENT_RESTARAUCAO_DISPARO_DE_ZONA_24H,
    AMT_EVENT_CODE_RESTARAUCAO_TAMPER_DO_TECLADO: AMT_EVENT_RESTARAUCAO_TAMPER_DO_TECLADO,
    AMT_EVENT_CODE_RESTARAUCAO_DISPARO_SILENCIOSO: AMT_EVENT_RESTARAUCAO_DISPARO_SILENCIOSO,
    AMT_EVENT_CODE_RESTARAUCAO_DA_SUPERVISAO_SMART: AMT_EVENT_RESTARAUCAO_DA_SUPERVISAO_SMART,
    AMT_EVENT_CODE_RESTARAUCAO_SOBRECARGA_NA_SAIDA_AUXILIAR: AMT_EVENT_RESTARAUCAO_SOBRECARGA_NA_SAIDA_AUXILIAR,
    AMT_EVENT_CODE_RESTARAUCAO_FALHA_NA_REDE_ELETRICA: AMT_EVENT_RESTARAUCAO_FALHA_NA_REDE_ELETRICA,
    AMT_EVENT_CODE_RESTARAUCAO_BAT_PRINC_BAIXA_OU_EM_CURTO_CIRCUITO: AMT_EVENT_RESTARAUCAO_BAT_PRINC_BAIXA_OU_EM_CURTO_CIRCUITO,
    AMT_EVENT_CODE_RESTARAUCAO_BAT_PRINC_AUSENTE_OU_INVERTIDA: AMT_EVENT_RESTARAUCAO_BAT_PRINC_AUSENTE_OU_INVERTIDA,
    AMT_EVENT_CODE_RESTARAUCAO_CORTE_OU_CURTO_CIRCUITO_NA_SIRENE: AMT_EVENT_RESTARAUCAO_CORTE_OU_CURTO_CIRCUITO_NA_SIRENE,
    AMT_EVENT_CODE_RESTARAUCAO_PROBLEMA_EM_TECLADO_OU_RECEPTOR: AMT_EVENT_RESTARAUCAO_PROBLEMA_EM_TECLADO_OU_RECEPTOR,
    AMT_EVENT_CODE_RESTARAUCAO_LINHA_TELEFONICA: AMT_EVENT_RESTARAUCAO_LINHA_TELEFONICA,
    AMT_EVENT_CODE_RESTARAUCAO_CORTE_DA_FIACAO_DOS_SENSORES: AMT_EVENT_RESTARAUCAO_CORTE_DA_FIACAO_DOS_SENSORES,
    AMT_EVENT_CODE_RESTARAUCAO_CURTO_CIRCUITO_NA_FIACAO_DOS_SENSORES: AMT_EVENT_RESTARAUCAO_CURTO_CIRCUITO_NA_FIACAO_DOS_SENSORES,
    AMT_EVENT_CODE_RESTARAUCAO_TAMPER_DO_SENSOR: AMT_EVENT_RESTARAUCAO_TAMPER_DO_SENSOR,
    AMT_EVENT_CODE_RESTARAUCAO_BATERIA_BAIXA_DE_SENSOR_SEM_FIO: AMT_EVENT_RESTARAUCAO_BATERIA_BAIXA_DE_SENSOR_SEM_FIO,
    AMT_EVENT_CODE_ATIVACAO_PELO_USUARIO: AMT_EVENT_ATIVACAO_PELO_USUARIO,
    AMT_EVENT_CODE_AUTO_ATIVACAO: AMT_EVENT_AUTO_ATIVACAO,
    AMT_EVENT_CODE_ATIVACAO_VIA_COMPUTADOR_OU_TELEFONE: AMT_EVENT_ATIVACAO_VIA_COMPUTADOR_OU_TELEFONE,
    AMT_EVENT_CODE_ATIVACAO_POR_UMA_TECLA: AMT_EVENT_ATIVACAO_POR_UMA_TECLA,
    AMT_EVENT_CODE_DESACIONAMENTO_DE_PGM: AMT_EVENT_DESACIONAMENTO_DE_PGM,
    AMT_EVENT_CODE_ATIVACAO_PARCIAL: AMT_EVENT_ATIVACAO_PARCIAL,
    AMT_EVENT_CODE_KEEP_ALIVE: AMT_EVENT_KEEP_ALIVE,
}

import crcengine

def _bcd_to_decimal(mbytes: bytes, unescape_zeros=True):
    """Convert a sequence of bcd encoded decimal to integer."""

    def unescape_zero(i: int):
        return i if i != 0xA else 0

    if unescape_zeros:
        mbytes = bytes(unescape_zero(b) for b in mbytes)

    len_mbytes = len(mbytes)
    return sum(10 ** (len_mbytes - i - 1) * b for i, b in enumerate(mbytes))


def _decimal_to_bcd_nibble(decimal: int):
    """Convert a decimal between 0 to 99 into two bcd encoded nibbles."""
    if decimal < 0 or decimal > 99:
        raise ValueError("argument must be non negative")

    ones = decimal % 10
    tens = decimal // 10

    return tens << 4 | ones

def _code_to_bcd(code: str):
    """Convert a password code into a BCD array."""
    result = bytes([])
    
    if len(code) % 2:
        code = "0" + code

    for i in range(len(code)//2):
        ch = (ord(code[i*2]) - ord('0'))*10
        cl = ord(code[i*2 + 1]) - ord('0')
        result += bytes([_decimal_to_bcd_nibble(ch + cl)])

    return result

class AMTAlarm:
    """Class that represents the alarm panel"""

    def checksum(self, value: bytes):
        res = 0
        for c in value:
            res = res ^ c
        res = res ^ 0xff
        res = res & 0xff
        return res

    def __init__(
            self, port : int, default_password=None, logger=logging.getLogger(__package__)
    ) -> None:
        """Initialize."""

        self.logger = logger
        self.default_password = None
        if default_password is not None:
            self.default_password = str(default_password)
            if len(self.default_password) != 4 and len(self.default_password) != 6:
                raise ValueError

        self.port = port
        self._timeout = 20.0

        self.polling_task = None
        self.reading_task = None
        self.model = None
        self.model_initialized_event = asyncio.Event()
        self.isecprogram_authenticated_event = asyncio.Event()
        self.initialized_event = asyncio.Event()

        self.socket: Union[None, socket.socket] = None
        self.client_socket: Union[None, socket.socket] = None
        self.writer: asyncio.StreamWriter = None
        self.reader: asyncio.StreamReader = None

        self.crc_isecprogram = crcengine.create(0x8005, 16, 0, False, False, "", 0)
        self.isecprogram_authenticated = False

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
        self.logger.debug("request zones called")

        if self.default_password is None:
            raise ValueError

        buf = bytes([])
        buf = buf + b"\xe9\x21"

        buf = buf + self.default_password.encode("utf-8")

        cmd = 0x5b

        buf = buf + bytes([cmd]) + b"\x21"

        await self.send_message(buf)


    async def send_isecprogram_set_datetime(self, newtime = time.time()):
        """Send Request Information packet."""
        self.logger.debug("isecprogram authentication")

        await self.send_isecprogram_authentication()
        await self.isecprogram_authenticated_event.wait()
        self.isecprogram_authenticated_event.clear()
        if self.isecprogram_authenticated:
            if self.default_password is None:
                raise ValueError

            buf = bytes([])
            buf = buf + b"\x18"

            await self.send_isecprogram_message(buf)
            (
                tm_year,
                tm_mon,
                tm_mday,
                tm_hour,
                tm_min,
                tm_sec,
                _,
                _,
                _,
            ) = time.localtime(newtime)
            tm_year -= 2000

            buf = buf + bytes(map(_decimal_to_bcd_nibble,
                                  [tm_year, tm_mon, tm_mday, tm_hour, tm_min, tm_sec]))
            await self.send_isecprogram_message(buf)
        else:
            self.logger.warning("Failed authenticating in ISECPROGRAM protocol")

    async def send_isecprogram_authentication(self):
        """Send Request Information packet."""
        self.logger.debug("isecprogram authentication")

        if self.default_password is None:
            raise ValueError

        buf = bytes([])
        buf = buf + b"\x11"

        buf = buf + _code_to_bcd(self.default_password)

        buf = buf + b"\x99"

        await self.send_isecprogram_message(buf)

    async def send_arm_partition(self, partition: int, code=None):
        """Send Arm Partition packet."""

        self.logger.info(f"arm partition {partition+1}")

        if code is None:
            code = self.default_password
        if code is None:
            raise ValueError

        buf = bytes([])
        buf = buf + b"\xe9\x21"

        buf = buf + code.encode("utf-8")

        buf = buf + b"\x41"
        buf = buf + bytes([0x40 + partition + 1])
        buf = buf + b"\x21"

        await self.send_message(buf)

    async def send_arm(self, code=None):
        """Send Arm packet."""

        self.logger.info(f"arm")

        if code is None:
            code = self.default_password
        if code is None:
            raise ValueError

        buf = bytes([])
        buf = buf + b"\xe9\x21"

        buf = buf + code.encode("utf-8")

        buf = buf + b"\x41"
        buf = buf + b"\x21"

        await self.send_message(buf)

    async def send_disarm_partition(self, partition: int, code=None):
        """Send Request Information packet."""

        self.logger.info(f"disarm partition {partition+1}")

        if code is None:
            code = self.default_password
        if code is None:
            raise ValueError

        buf = bytes([])
        buf = buf + b"\xe9\x21"

        buf = buf + code.encode("utf-8")

        buf = buf + b"\x44"
        buf = buf + bytes([0x40 + partition + 1])
        buf = buf + b"\x21"

        await self.send_message(buf, self.checksum)

    async def send_disarm(self, code=None):
        """Send Disarm packet."""

        self.logger.info(f"disarm")

        if code is None:
            code = self.default_password
        if code is None:
            raise ValueError

        buf = bytes([])
        buf = buf + b"\xe9\x21"

        buf = buf + code.encode("utf-8")

        buf = buf + b"\x44"
        buf = buf + b"\x21"

        await self.send_message(buf, self.checksum)

    async def _send_trigger(self, code=None, panico_type=1):
        if code is None:
            code = self.default_password
        if code is None:
            raise ValueError

        buf = bytes([])
        buf = buf + b"\xe9\x21"

        buf = buf + code.encode("utf-8")

        cmd = 0x45

        buf = buf + bytes([cmd, panico_type]) + b"\x21"

        await self.send_message(buf)

    async def send_audible_trigger(self, code=None):
        """Send request packet to Trigger the alarm."""
        self.logger.debug("send trigger called")
        await self._send_trigger(code)

    async def send_silent_trigger(self, code=None):
        """Send request packet to Trigger the alarm."""
        self.logger.debug("send trigger called")
        silent_panico_type = 0
        await self._send_trigger(code, silent_panico_type)

    async def send_medical_trigger(self, code=None):
        """Send request packet to Trigger the alarm."""
        medical_panico_type = 0
        await self._send_trigger(code, medical_panico_type)

    async def send_fire_trigger(self, code=None):
        """Send request packet to Trigger the alarm."""
        fire_panico_type = 0
        await self._send_trigger(code, fire_panico_type)

    async def send_bypass(self, zones: list[int], code=None):
        """Send bypass packet alarm."""
        self.logger.debug("send bypass")

        if code is None:
            code = self.default_password
        if code is None:
            raise ValueError

        state = bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00')

        for i in range(8):
            for j in range(8):
                if (i*8 + j) in zones:
                    state[i] |= 1 << j

        buf = bytes([])
        buf = buf + b"\xe9\x21"
        buf = buf + code.encode("utf-8") + bytes([0x42])
        buf = buf + state + b"\x21"

        await self.send_message(buf)

    async def __send_ack(self):
        try:
            self.writer.write(bytes([0xFE]))
            await self.writer.drain()
        except OSError as e:
            self.polling_task = None
            self.logger.error(f"Connection error {str(e)}")
            await self.__accept_new_connection()
        except Exception as e:
            self.polling_task = None
            self.logger.error(f"Some unknown error {str(e)}")
            await self.__accept_new_connection()
            raise

    async def send_raw_message(self, packet: bytes):
        """Send packet."""
        try:
            self.logger.debug(f"sending {packet.hex()}")
            self.writer.write(packet)
            await self.writer.drain()
        except OSError as e:
            self.polling_task = None
            self.logger.error(f"Connection error {str(e)}")
            await self.__accept_new_connection()
        except Exception as e:
            self.polling_task = None
            self.logger.error(f"Some unknown error {str(e)}")
            await self.__accept_new_connection()
            raise

    async def send_message(self, packet: bytes, crcengine=None):
        """Send packet."""
        self.logger.debug(f"Sending message with contents {packet.hex()}")

        if crcengine is None:
            crcengine = self.checksum

        buf = bytes([len(packet)]) + packet
        crc = crcengine(buf + bytes([0]))
        await self.send_raw_message(buf + bytes([crc]))

    async def send_isecprogram_message(self, packet: bytes, crcengine=None):
        """Send packet."""

        if crcengine == None:
            crcengine = self.checksum

        crc = self.crc_isecprogram(bytes([len(packet)]) + packet)

        print(f"=================================== crc is {crc}")

        buf = b"\xe7" + bytes([len(packet)]) + packet + bytes([crc >> 8, crc & 0xFF])

        print (f"buf is {buf.hex()}")
            
        buf = bytes([len(buf)]) + buf
        v1_crc = crcengine(buf + bytes([0]))
        print (f"whole packet {(buf + bytes([v1_crc])).hex()}")
        await self.send_raw_message(buf + bytes([v1_crc]))

    def __handle_amt_event(self, event: int, partition: int, zone: int, client_id: int):
        if event in (
            AMT_EVENT_CODE_DESATIVACAO_PELO_USUARIO,
            AMT_EVENT_CODE_AUTO_DESATIVACAO,
            AMT_EVENT_CODE_DESATIVACAO_VIA_COMPUTADOR_OU_TELEFONE,
        ):
            if partition == -1:
                self.partitions = [False] * self.max_partitions
                self.triggered_partitions = [False] * self.max_partitions
                self.triggered_sensors = [False] * self.max_sensors
            else:
                self.partitions[partition] = False
                self.triggered_partitions = [False] * self.max_partitions
                self.triggered_sensors = [False] * self.max_sensors
        elif event in (
            AMT_EVENT_CODE_ATIVACAO_PELO_USUARIO,
            AMT_EVENT_CODE_AUTO_ATIVACAO,
            AMT_EVENT_CODE_ATIVACAO_VIA_COMPUTADOR_OU_TELEFONE,
            AMT_EVENT_CODE_ATIVACAO_POR_UMA_TECLA,
            AMT_EVENT_CODE_ATIVACAO_PARCIAL,
        ):
            self.logger.info(f"Activated partition (untriggering too) {partition}")
            if partition != -1 and zone != -1 and zone < self.max_sensors:
                self.triggered_sensors[zone] = False
            if partition == -1:
                self.triggered_partitions = [False] * self.max_partitions
            else:
                self.triggered_partitions[partition] = False

            if partition == -1:
                self.partitions = [True] * self.max_partitions
            else:
                self.partitions[partition] = True
        if event == AMT_EVENT_CODE_FALHA_AO_COMUNICAR_EVENTO:
            self.logger.error(f"Alarm panel error: {AMT_EVENT_MESSAGES[event]}")
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
            self.logger.info(f"Triggering partition {partition}")
            # self.logger.error(
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
            self.logger.info(f"Untriggering partition {partition}")
            if partition != -1 and zone != -1 and zone < self.max_sensors:
                self.triggered_sensors[zone] = False
            if partition == -1:
                self.triggered_partitions = [False] * self.max_partitions
            else:
                self.triggered_partitions[partition] = False
        self.__call_listeners()

    async def __handle_packet(self, packet: bytes):
        self.logger.debug ('received packet packet ' + packet.hex())
        if len(packet) > 0:
            cmd = packet[0]
            if cmd == AMT_REQ_CODE_MODELO and len(packet) > 1:
                # no ack because it is a response
                self.model = (packet[1:]).decode("utf-8")
                self.model_initialized_event.set()
                self.logger.debug(f"Model is {self.model}")
            elif cmd == AMT_COMMAND_CODE_HEARTBEAT and len(packet) == 1:
                await self.__send_ack()
            # elif cmd == 0x94:
            elif cmd == AMT_COMMAND_CODE_CONECTAR:
                if len(self._mac_address) == 0:
                    self._mac_address = packet[4:7]
                self.logger.debug(f"MAC is {self._mac_address}")

                self.initialized_event.set()
                await self.__send_ack()
                await self.send_request_model()
            elif cmd == AMT_REQ_CODE_MAC and len(packet) == 7:
                self._mac_address = packet[1:7]
            # elif cmd == 0xB0 and len(packet) == 17 and packet[1] == 0x12:
            elif (
                    cmd == AMT_COMMAND_CODE_EVENT_CONTACT_ID # 0xb0
            ):
                if len(packet) == 17 and (packet[1] == 0x11 or packet[1] == 0x12):
                    client_id = _bcd_to_decimal(packet[2:6])
                    ev_id = _bcd_to_decimal(packet[8:12])
                    partition = _bcd_to_decimal(packet[12:14]) - 1
                    zone = _bcd_to_decimal(packet[14:17])

                    self.__handle_amt_event(ev_id, partition, zone, client_id)

                    await self.__send_ack()
                else:
                    logger.warning("AMT_COMMAND_CODE_EVENT_CONTACT_ID received, but couldn't parse with size ", len(packet))
            elif (
                    cmd == AMT_COMMAND_CODE_EVENT_DATA_HORA
            ):
                if len(packet) == 29 and (packet[1] == 0x11 or packet[1] == 0x12):
                    client_id = _bcd_to_decimal(packet[2:6])
                    ev_id = _bcd_to_decimal(packet[8:12])
                    partition = _bcd_to_decimal(packet[12:14]) - 1
                    zone = _bcd_to_decimal(packet[14:17])
                    data_evento = datetime.datetime(packet[19], packet[18], packet[17],
                                                    packet[20], packet[21], packet[22])
                    self.logger.info("event with time and date", ev_id, "from partition", partition, "and zone", zone,
                                     "datetime", data_event)
                else:
                    logger.warning("AMT_COMMAND_CODE_EVENT_DATA_HORA received, but couldn't parse with size ", len(packet))
            elif cmd == AMT_COMMAND_CODE_SOLICITA_DATA_HORA:
                self.logger.info("sending datetime response to alarm panel")
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
            elif cmd == AMT_PROTOCOL_ISECPROGRAM and len(packet) >= 4:
                if packet[1] == 1 and packet[2] == 0x50:
                    self.isecprogram_authenticated = True
                    self.isecprogram_authenticated_event.set()
                elif packet[1] == 1 and packet[2] == 0x53:
                    self.logger.error("Authentication failed")
                    self.isecprogram_authenticated_event.set()
            elif cmd == AMT_PROTOCOL_ISEC_MOBILE and len(packet) == 2:
                if packet[1] == AMT_ISEC_MOBILE_COMMAND_CODE_COMAND_ACCEPTED:
                    await self.__send_ack()
                else:
                    if packet[1] == AMT_ISEC_MOBILE_COMMAND_CODE_INVALID_PASSWORD:
                        self.logger.error("We are using wrong password in AMT integration?")
                    elif packet[1] == AMT_ISEC_MOBILE_COMMAND_CODE_INVALID_COMMAND:
                        self.logger.error("Invalid Command")
                    elif packet[1] == AMT_ISEC_MOBILE_COMMAND_CODE_NOT_PARTITIONED:
                        self.logger.error("Not partitioned")
                    elif packet[1] == AMT_ISEC_MOBILE_COMMAND_CODE_OPEN_ZONES:
                        self.logger.error("Open Zones")
                    elif packet[1] == AMT_ISEC_MOBILE_COMMAND_CODE_DEPRECATED_COMMAND:
                        self.logger.error("Deprecated command")
                    elif packet[1] == AMT_ISEC_MOBILE_COMMAND_CODE_NO_PERMISSION_BY_PASS:
                        self.logger.error("No permission to by pass")
                    elif packet[1] == AMT_ISEC_MOBILE_COMMAND_CODE_NO_PERMISSION:
                        self.logger.error("No permission for this command")
                    elif packet[1] == AMT_ISEC_MOBILE_COMMAND_CODE_ARMED:
                        self.logger.error("Already armed")
                    elif packet[1] == AMT_ISEC_MOBILE_COMMAND_CODE_NO_ZONES:
                        self.logger.error("No zones configured")
                    else:
                        self.logger.error("Some unknown error")
                    await self.__send_ack()
            elif cmd == AMT_PROTOCOL_ISEC_MOBILE and len(packet) >= 54+1:
                self.logger.debug(f"e9 update all partitions and zones, size {len(packet)}")
                self.logger.debug(packet.hex())
                for x in range(6):
                    for i in range(8): # starts in byte 1 and go up to byte 8
                        c = packet[x + 1]
                        self.open_sensors[x * 8 + i] = ((c >> i) & 1) == 1

                    for i in range(8): # starts in byte 9 and go up to byte 16
                        c = packet[x + 1 + 8]
                        self.triggered_sensors[x * 8 + i] = ((c >> i) & 1) == 1

                    for i in range(8): # starts in byte 17 and go up to byte 24
                        c = packet[x + 1 + 16]
                        self.bypassed_sensors[x * 8 + i] = ((c >> i) & 1) == 1

                c = packet[28]
                for i in range(2):
                    self.partitions[i] = bool((c >> i) & 1)

                c = packet[29]
                for i in range(2):
                    self.partitions[i + 2] = bool((c >> i) & 1)

                c = packet[30]
                self.logger.debug(f"byte returned {c}")
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

                if self.siren_activated or self.zones_triggered or self.panel_activated or self.problem_detected:
                    self.logger.warning(f"siren {self.siren_activated} zone triggered {self.zones_triggered} panel activated {self.panel_activated} problem_detected {self.problem_detected}")
                if self.overload_aux or self.battery_short_circuit or self.battery_not_found or self.battery_low or self.power_out:
                    self.logger.warning(f"overload aux {self.overload_aux} battery_short_circuit {self.battery_short_circuit} battery_not_found {self.battery_not_found} battery_low {self.battery_low} power_out {self.power_out}")

                c = packet[43]
                self.error_communicating_event = bool((c >> 3) & 1)
                self.error_telephone_line = bool((c >> 2) & 1)
                self.error_siren_short_circuit = bool((c >> 1) & 1)
                self.error_siren_cut = bool((c >> 0) & 1)

                if self.error_communicating_event or self.error_telephone_line or self.error_siren_short_circuit or self.error_siren_cut:
                    self.logger.warning(f"(error) communication event {self.error_communicating_event} telephone line {self.error_telephone_line} siren_short_circuit {self.error_siren_short_circuit} siren cut {self.error_siren_cut}")

                self.__call_listeners()
            else:
                self.logger.error(f"AMT doesn't know how to deal with {packet.hex()} ?")

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
                if self.checksum(buf) != 0:
                    print(
                        "Buffer %s doesn't match CRC, which should be %d but actually was %d",
                        buf,
                        self.checksum(buf),
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

        while True:
            try:
                await self.send_request_zones()
                await asyncio.sleep(1)

                if (
                    self._read_timestamp is not None
                    and time.monotonic() - self._read_timestamp >= self._timeout
                ):
                    self.polling_task = None
                    self.logger.error(f"Timeout error {(time.monotonic() - self._read_timestamp)}")
                    await self.__accept_new_connection()
                    return

            except OSError as ex:
                self.polling_task = None
                self.logger.error(f"Connection error {ex}")
                await self.__accept_new_connection()
                return
            except Exception as ex:
                self.polling_task = None
                self.logger.error(f"Some unknown error {ex}")
                await self.__accept_new_connection()
                raise

    async def __handle_read_from_stream(self):
        """Handle read data from alarm."""

        while True:
            self._read_timestamp = time.monotonic()
            data = await self.reader.read(4096)
            if self.reader.at_eof():
                self.reading_task = None
                self.logger.info("Connection dropped by other side")
                await self.__accept_new_connection()
                return

            self.outstanding_buffer += data

            try:
                await self.__handle_data()
            except Exception as ex:
                self.logger.error(f"Some unknown error {ex}")
                await self.__accept_new_connection()
                raise

    async def unique(self) -> str:
        await self.model_initialized_event.wait()
        return self.model + ' ' + self._mac_address.hex()

    async def wait_connection(self) -> bool:
        """Test if we can authenticate with the host."""

        self.logger.debug(
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
                self.logger.debug("Connection accepted")
            except asyncio.TimeoutError:
                self.logger.error(
                    "Timeout waiting on connection from Alarm Panel (60s). Retrying"
                )
                continue
            try:
                (self.reader, self.writer) = await asyncio.open_connection(
                    None, sock=self.client_socket
                )
            except asyncio.TimeoutError:
                self.logger.error(
                    "Timeout opening connection from Alarm Panel (60s). Retrying"
                )
                continue
            # print("Connection from Alarm Panel established", file=sys.stderr)
            self.__call_listeners()
            break

        return True

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
        if self.polling_task is None:
            self.polling_task = asyncio.create_task(self.__handle_polling())
        if self.reading_task is None:
            self.reading_task = asyncio.create_task(self.__handle_read_from_stream())

        await self.initialized_event.wait()
        await self.model_initialized_event.wait()

    async def wait_connection_and_update(self):
        """Call asynchronously wait_connection and then after a update."""
        await self.wait_connection()
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
