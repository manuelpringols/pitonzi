#!/usr/bin/env python3

import sys
import socket
import os
from impacket.smbconnection import SMBConnection
from impacket import smb

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    BRIGHT_RED = '\033[91;1m'
    YELLOW = '\033[93m'
    RESET = '\033[0m'

def print_status(ip, message, color):
    print(f"{color}{ip}: {message}{Colors.RESET}")

def check_port_445(ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        sock.connect((ip, 445))
        sock.close()
        return True
    except:
        return False

def check_smbv1(ip):
    try:
        conn = SMBConnection(ip, ip, timeout=3)
        conn.login('', '')  # Anonymous login
        dialect = conn.getDialect()
        conn.close()
        return dialect <= 0x0110  # SMBv1
    except:
        return False

def deep_eternalblue_probe(ip):
    try:
        conn = SMBConnection(ip, ip, timeout=3)
        conn.login('', '')

        tid = conn.tree_connect_andx(r'\\%s\\IPC$' % ip)
        conn.connectTree(tid)

        fid = conn.openFile(tid, "srvsvc", smb.SMB_O_RDONLY)
        conn.close()
        return False
    except Exception as e:
        if "STATUS_INSUFF_SERVER_RESOURCES" in str(e):
            return True
        return False

def check_eternalblue_full(ip):
    if not check_port_445(ip):
        print_status(ip, "Porta 445 CHIUSA o NON raggiungibile", Colors.YELLOW)
        return

    if not check_smbv1(ip):
        print_status(ip, "Sistema NON vulnerabile: SMBv1 NON attivo", Colors.GREEN)
        return

    if deep_eternalblue_probe(ip):
        print_status(ip, "⚠️ VULNERABILITÀ CRITICA: EternalBlue BREACH POSSIBILE – PATCH IMMEDIATA!", Colors.BRIGHT_RED)
    else:
        print_status(ip, "SMBv1 attivo: POTENZIALMENTE vulnerabile, MA NO SEGNI di breach immediato", Colors.RED)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Uso: {sys.argv[0]} <IP o file.txt>")
        sys.exit(1)

    input_arg = sys.argv[1]

    # Se è un file, leggi ogni IP da file
    if os.path.isfile(input_arg):
        with open(input_arg, 'r') as f:
            for line in f:
                ip = line.strip()
                if ip:
                    check_eternalblue_full(ip)
    else:
        # Altrimenti tratta l'argomento come singolo IP
        check_eternalblue_full(input_arg)
