#!/usr/bin/env python3

import sys
import socket
from impacket.smbconnection import SMBConnection
from netaddr import IPNetwork
from impacket import smb

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    BRIGHT_RED = '\033[91;1m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
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
        return False  # Se tutto fila liscio, non vulnerabile
    except Exception as e:
        if "STATUS_INSUFF_SERVER_RESOURCES" in str(e):
            return True  # Pattern classico di MS17-010
        return False

def check_eternalblue_full(ip):
    if not check_port_445(ip):
        print_status(ip, "Porta 445 CHIUSA o NON raggiungibile", Colors.YELLOW)
        return 'PORT_CLOSED'

    if not check_smbv1(ip):
        print_status(ip, "Sistema NON vulnerabile: SMBv1 NON attivo", Colors.GREEN)
        return 'NOT_VULNERABLE'

    # SMBv1 attivo — potenzialmente vulnerabile
    if deep_eternalblue_probe(ip):
        print_status(ip, "⚠️ VULNERABILITÀ CRITICA: EternalBlue BREACH POSSIBILE – PATCH IMMEDIATA!", Colors.BRIGHT_RED)
        return 'CRITICALLY_VULNERABLE'
    else:
        print_status(ip, "SMBv1 attivo: POTENZIALMENTE vulnerabile, MA NO SEGNI di breach immediato", Colors.RED)
        return 'POTENTIALLY_VULNERABLE'

def expand_targets(arg):
    try:
        return list(IPNetwork(arg))
    except:
        return [arg]

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Uso: {sys.argv[0]} <IP|subnet>")
        print("Esempio:")
        print(f"  {sys.argv[0]} 192.168.1.10")
        print(f"  {sys.argv[0]} 192.168.1.0/24")
        sys.exit(1)

    targets = expand_targets(sys.argv[1])
    for ip in targets:
        check_eternalblue_full(str(ip))

