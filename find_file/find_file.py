#!/usr/bin/env python3

import subprocess
import os
import sys
import platform
import pyperclip

def get_package_manager():
    os_name = platform.system()

    if os_name == "Linux":
        try:
            with open("/etc/os-release") as f:
                os_release = f.read().lower()
        except FileNotFoundError:
            os_release = ""

        if "ubuntu" in os_release or "debian" in os_release:
            return os_name, "debian/ubuntu", "apt"
        elif "fedora" in os_release or "red hat" in os_release or "centos" in os_release:
            return os_name, "fedora/centos/rhel", "dnf"
        elif "arch" in os_release:
            return os_name, "arch", "pacman"
        elif "opensuse" in os_release:
            return os_name, "opensuse", "zypper"
        else:
            for pm in ["apt", "dnf", "yum", "pacman", "zypper"]:
                if subprocess.run(["which", pm], capture_output=True).returncode == 0:
                    return os_name, "linux-unknown", pm
            return os_name, "linux-unknown", None

    elif os_name == "Darwin":
        return os_name, "macos", "brew"
    elif os_name == "Windows":
        for pm in ["winget", "choco"]:
            if subprocess.run(["where", pm], capture_output=True, shell=True).returncode == 0:
                return os_name, "windows", pm
        return os_name, "windows", None
    else:
        return os_name, None, None

def install_package(package_name):
    os_name, distro, pm = get_package_manager()
    if pm is None:
        print(f"❌ Package manager non trovato per sistema {os_name} / {distro}", file=sys.stderr)
        return False

    if pm == "apt":
        subprocess.run(["sudo", "apt", "update"], check=True)
        cmd = ["sudo", "apt", "install", "-y", package_name]
    elif pm == "dnf":
        cmd = ["sudo", "dnf", "install", "-y", package_name]
    elif pm == "yum":
        cmd = ["sudo", "yum", "install", "-y", package_name]
    elif pm == "pacman":
        cmd = ["sudo", "pacman", "-Sy", package_name]
    elif pm == "zypper":
        cmd = ["sudo", "zypper", "install", "-y", package_name]
    elif pm == "brew":
        cmd = ["brew", "install", package_name]
    elif pm == "winget":
        cmd = ["winget", "install", "--id", package_name]
    elif pm == "choco":
        cmd = ["choco", "install", package_name, "-y"]
    else:
        print(f"❌ Package manager {pm} non supportato", file=sys.stderr)
        return False

    print(f"📦 Installazione del pacchetto: {package_name}")
    subprocess.run(cmd, check=True)
    return True

def copy_to_clipboard(text):
    try:
        pyperclip.copy(text)
        print("📋 Directory copiata negli appunti!", file=sys.stderr)
    except pyperclip.PyperclipException:
        print("⚠️ Clipboard non supportata o mancano tool necessari.", file=sys.stderr)
        os_name, _, _ = get_package_manager()
        if os_name == "Linux":
            print("Vuoi installare 'xclip' per abilitare la clipboard? (s/N): ", end="")
            choice = input().strip().lower()
            if choice == "s":
                install_package("xclip")
                print("Riprova ad eseguire lo script.", file=sys.stderr)
        elif os_name == "Darwin":
            print("Assicurati che 'pbcopy' sia disponibile su MacOS.", file=sys.stderr)
        else:
            print("Clipboard non supportata su questo sistema.", file=sys.stderr)

def has_sudo():
    try:
        subprocess.check_call("sudo -n true", shell=True,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def main():
    pattern = input("Inserisci parte del nome file da cercare: ").strip()
    if not pattern:
        return

    if has_sudo():
        find_command = f"sudo find / \\( -path /proc -o -path /sys -o -path /dev \\) -prune -o -type f -name '*{pattern}*' -print 2>/dev/null"
    else:
        home = os.path.expanduser("~")
        find_command = f"find {home} -type f -name '*{pattern}*' 2>/dev/null"

    try:
        fzf_command = f"bash -c \"{find_command} | fzf --prompt='Seleziona file> '\""
        selected_file = subprocess.check_output(fzf_command, shell=True, text=True).strip()
        if not selected_file:
            return

        dir_path = os.path.dirname(selected_file)
        if os.access(dir_path, os.X_OK):
            print(dir_path)
            copy_to_clipboard(dir_path)
        else:
            pwd = os.getcwd()
            print(pwd)
            print(f"⚠️ Nessun permesso per accedere a {dir_path}. Mostro la directory corrente.", file=sys.stderr)

    except subprocess.CalledProcessError:
        pass

if __name__ == "__main__":
    main()
