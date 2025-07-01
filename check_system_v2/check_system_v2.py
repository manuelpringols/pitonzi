import psutil
import platform
import matplotlib.pyplot as plt
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
import datetime
import os
import socket
import subprocess

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
        raise EnvironmentError(f"Package manager non trovato per sistema {os_name} / {distro}")

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
        raise EnvironmentError(f"Package manager {pm} non supportato")

    print(f"Eseguo il comando: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)

def check_tool_installed(tool):
    return subprocess.run(["which", tool], capture_output=True).returncode == 0

def ask_user(question):
    reply = input(f"{question} (y/n): ").lower().strip()
    return reply in ["y", "yes"]

def get_battery_cycles_linux():
    base_paths = ["/sys/class/power_supply/BAT0", "/sys/class/power_supply/BAT1"]

    for base in base_paths:
        cycle_file = os.path.join(base, "cycle_count")
        if os.path.exists(cycle_file):
            try:
                with open(cycle_file, "r") as f:
                    cycles = int(f.read().strip())
                    return cycles, None
            except Exception as e:
                return None, str(e)
    try:
        output = subprocess.check_output(["upower", "-i", "/org/freedesktop/UPower/devices/battery_BAT0"], text=True)
        for line in output.splitlines():
            if "cycle count" in line.lower():
                return int(line.split(":")[1].strip()), None
    except Exception as e:
        return None, str(e)

    return None, "Cicli non trovati"


def estimate_battery_condition(cycles):
    """
    Stima condizione basata sui cicli reali:
    - Nuova: <100
    - Buona: <300
    - Usurata: <500
    - Pessime condizioni: >=500
    """
    if cycles is None:
        return "❓ Condizione sconosciuta"

    if cycles < 100:
        return "🟢 Nuova"
    elif cycles < 300:
        return "🟡 Buona"
    elif cycles < 500:
        return "🟠 Usurata"
    else:
        return "🔴 Pessime condizioni"

def get_battery_info():
    battery = psutil.sensors_battery()
    if battery is None:
        return "🔋 <b>Batteria</b><br/>Nessuna batteria rilevata"

    percent = battery.percent
    plugged = battery.power_plugged
    time_left = ""

    if not plugged:
        if battery.secsleft != psutil.POWER_TIME_UNLIMITED and battery.secsleft != psutil.POWER_TIME_UNKNOWN:
            mins = battery.secsleft // 60
            hours = mins // 60
            mins = mins % 60
            time_left = f"{hours}h {mins}m"
        else:
            time_left = "Tempo rimanente non disponibile"
    else:
        time_left = "In carica"

    # ➡️ Cicli di carica su Linux
    os_name, distro, pm = get_package_manager()
    if os_name == "Linux":
        cycles, cycle_err = get_battery_cycles_linux()
    else:
        cycles, cycle_err = None, "⚠️ Non implementato per questo OS"

    condition = estimate_battery_condition(cycles)

    battery_info = (
        f"🔋 <b>Batteria</b><br/>"
        f"Percentuale: {percent}%<br/>"
        f"Collegata a corrente: {'Sì' if plugged else 'No'}<br/>"
        f"Tempo rimanente: {time_left}<br/>"
        f"Cicli di carica: {cycles if cycles is not None else cycle_err}<br/>"
        f"Condizione stimata: {condition}"
    )
    return battery_info
 
try:
    import GPUtil
    gpu_available = True
except ImportError:
    gpu_available = False

# ✅ Funzione: formatta dimensioni file
def get_size(bytes, suffix="B"):
    factor = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if bytes < factor:
            return f"{bytes:.2f}{unit}{suffix}"
        bytes /= factor

# ✅ Funzione: genera grafico CPU con colori gradienti
def generate_cpu_chart():
    cpu_percentages = psutil.cpu_percent(percpu=True, interval=1)
    cores = [f'Core {i}' for i in range(len(cpu_percentages))]
    colors_bars = []

    for percent in cpu_percentages:
        if percent > 80:
            colors_bars.append('red')
        elif percent > 50:
            colors_bars.append('orange')
        elif percent > 30:
            colors_bars.append('yellowgreen')
        else:
            colors_bars.append('lightgreen')

    plt.figure(figsize=(10,5))
    bars = plt.bar(cores, cpu_percentages, color=colors_bars)
    plt.ylabel('Utilizzo (%)')
    plt.ylim(0, 100)
    plt.title('Utilizzo CPU per core')

    for bar, percent in zip(bars, cpu_percentages):
        plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1, f"{percent}%", ha='center')

    plt.tight_layout()
    plt.savefig('cpu_usage.png')
    plt.close()

# ✅ Funzione: genera grafico RAM
def generate_ram_chart():
    ram = psutil.virtual_memory()
    labels = ['Usata', 'Libera']
    sizes = [ram.used, ram.available]
    colors_pie = ['purple', 'lightgreen']

    plt.figure(figsize=(6,6))
    plt.pie(sizes, labels=[f"{l} ({get_size(s)})" for l,s in zip(labels,sizes)],
            colors=colors_pie, autopct='%1.1f%%', startangle=140)
    plt.title('Utilizzo RAM')
    plt.tight_layout()
    plt.savefig('ram_usage.png')
    plt.close()

# ✅ Funzione: genera grafico disco
def generate_disk_chart():
    partitions = psutil.disk_partitions()
    for p in partitions:
        try:
            usage = psutil.disk_usage(p.mountpoint)
            plt.figure(figsize=(5,5))
            labels = ['Usato', 'Libero']
            sizes = [usage.used, usage.free]
            colors_pie = ['orange', 'lightblue']
            plt.pie(sizes, labels=[f"{l} ({get_size(s)})" for l,s in zip(labels,sizes)],
                    autopct='%1.1f%%', startangle=140, colors=colors_pie)
            plt.title(f'Utilizzo Disco: {p.mountpoint}')
            plt.tight_layout()
            filename = f'disk_usage_{p.mountpoint.strip("/").replace("/", "_")}.png'
            plt.savefig(filename)
            plt.close()
        except PermissionError:
            continue

# ✅ Funzione: genera PDF
def generate_pdf_report(filename):
    doc = SimpleDocTemplate(filename, pagesize=A4)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='Heading1Centered', parent=styles['Heading1'], alignment=1, textColor=colors.darkblue))
    styles.add(ParagraphStyle(name='Heading2Colored', parent=styles['Heading2'], textColor=colors.darkblue))
    normal_style = ParagraphStyle(name='NormalColored', parent=styles['Normal'], textColor=colors.black)

    Story = []

    # 📝 Titolo
    Story.append(Paragraph("🖥️ System Checkup Report", styles['Heading1Centered']))
    Story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
    Story.append(Spacer(1,12))

    # ℹ️ Info sistema
    uname = platform.uname()
    Story.append(Paragraph(f"<b>🖥️ Sistema:</b> {uname.system}", normal_style))
    Story.append(Paragraph(f"<b>🖥️ Nome Nodo:</b> {uname.node}", normal_style))
    Story.append(Paragraph(f"<b>🔧 Versione:</b> {uname.version}", normal_style))
    Story.append(Paragraph(f"<b>💻 Macchina:</b> {uname.machine}", normal_style))
    Story.append(Paragraph(f"<b>🧠 Processore:</b> {uname.processor or 'Non disponibile'}", normal_style))

    # ✅ GPU info
    if gpu_available:
        gpus = GPUtil.getGPUs()
        if gpus:
            Story.append(Spacer(1,12))
            Story.append(Paragraph("<b>🖥️ GPU Details</b>", styles['Heading2Colored']))
            for gpu in gpus:
                Story.append(Paragraph(f"{gpu.name} ({gpu.driver}) - Utilizzo: {gpu.load*100:.1f}%", normal_style))
                Story.append(Paragraph(f"Memoria: {get_size(gpu.memoryUsed*1024**2)} / {get_size(gpu.memoryTotal*1024**2)}", normal_style))

    # ✅ CPU dettagliata
    Story.append(Spacer(1,12))
    Story.append(Paragraph("<b>🔧 CPU Details</b>", styles['Heading2Colored']))
    freq = psutil.cpu_freq()
    if freq:
        Story.append(Paragraph(f"Frequenza attuale: {freq.current:.2f} Mhz", normal_style))
        Story.append(Paragraph(f"Frequenza massima: {freq.max:.2f} Mhz", normal_style))
    Story.append(Paragraph(f"Core fisici: {psutil.cpu_count(logical=False)}", normal_style))
    Story.append(Paragraph(f"Core logici: {psutil.cpu_count(logical=True)}", normal_style))

    # ✅ RAM dettagliata
    Story.append(Spacer(1,12))
    Story.append(Paragraph("<b>💾 RAM Details</b>", styles['Heading2Colored']))
    ram = psutil.virtual_memory()
    Story.append(Paragraph(f"Totale: {get_size(ram.total)}", normal_style))
    Story.append(Paragraph(f"Usata: {get_size(ram.used)}", normal_style))
    Story.append(Paragraph(f"Disponibile: {get_size(ram.available)}", normal_style))
    Story.append(Paragraph(f"Percentuale usata: {ram.percent}%", normal_style))

    # ✅ Swap
    swap = psutil.swap_memory()
    Story.append(Paragraph(f"Swap usato: {get_size(swap.used)} / {get_size(swap.total)} ({swap.percent}%)", normal_style))

    # ✅ Batteria
    battery = psutil.sensors_battery()
    if battery:
        Story.append(Spacer(1,12))
        Story.append(Paragraph("<b>🔋 Batteria</b>", styles['Heading2Colored']))
        Story.append(Paragraph(f"Percentuale: {battery.percent}%", normal_style))
        Story.append(Paragraph(f"Collegato a corrente: {'Sì' if battery.power_plugged else 'No'}", normal_style))

    # ✅ Carico medio
    if hasattr(os, 'getloadavg'):
        load1, load5, load15 = os.getloadavg()
        Story.append(Paragraph(f"⚙️ Load Average (1/5/15 min): {load1:.2f} / {load5:.2f} / {load15:.2f}", normal_style))

    # ✅ Processi e thread
    Story.append(Spacer(1,12))
    Story.append(Paragraph(f"<b>📊 Processi attivi:</b> {len(psutil.pids())}", normal_style))
    Story.append(Paragraph(f"<b>🧵 Thread totali:</b> {sum(p.num_threads() for p in psutil.process_iter())}", normal_style))

    # ✅ Temperatura CPU
    try:
        temps = psutil.sensors_temperatures()
        if temps:
            Story.append(Spacer(1,12))
            Story.append(Paragraph("<b>🌡️ Temperature</b>", styles['Heading2Colored']))
            for name, entries in temps.items():
                for entry in entries:
                    Story.append(Paragraph(f"{entry.label or name}: {entry.current}°C", normal_style))
    except Exception:
        pass

    # ✅ Uptime
    uptime = datetime.datetime.now() - datetime.datetime.fromtimestamp(psutil.boot_time())
    Story.append(Spacer(1,12))
    Story.append(Paragraph(f"<b>⏳ Uptime:</b> {str(uptime).split('.')[0]}", normal_style))

    # ✅ Rete dettagliata
    Story.append(Spacer(1,12))
    Story.append(Paragraph("<b>🌐 Network</b>", styles['Heading2Colored']))
    addrs = psutil.net_if_addrs()
    for iface, addr_list in addrs.items():
        for addr in addr_list:
            if addr.family == socket.AF_INET:
                Story.append(Paragraph(f"{iface}: {addr.address}", normal_style))
    net_io = psutil.net_io_counters()
    Story.append(Paragraph(f"Totale inviati: {get_size(net_io.bytes_sent)}", normal_style))
    Story.append(Paragraph(f"Totale ricevuti: {get_size(net_io.bytes_recv)}", normal_style))

    # 🗓 Data e ora
    now = datetime.datetime.now()
    Story.append(Spacer(1,12))
    Story.append(Paragraph(f"<b>📅 Data report:</b> {now.strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    Story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
    Story.append(Spacer(1,12))

    # 📊 Grafici
    generate_cpu_chart()
    generate_ram_chart()
    generate_disk_chart()

    Story.append(Paragraph("<b>📊 Utilizzo CPU</b>", styles['Heading2Colored']))
    Story.append(Image('cpu_usage.png', width=400, height=200))
    Story.append(Spacer(1,12))

    Story.append(Paragraph("<b>📊 Utilizzo RAM</b>", styles['Heading2Colored']))
    Story.append(Image('ram_usage.png', width=300, height=300))
    Story.append(Spacer(1,12))

    # 📊 Grafici disco
    partitions = psutil.disk_partitions()
    for p in partitions:
        filename = f'disk_usage_{p.mountpoint.strip("/").replace("/", "_")}.png'
        if os.path.exists(filename):
            Story.append(Paragraph(f"<b>💾 Disco: {p.mountpoint}</b>", styles['Heading2Colored']))
            Story.append(Image(filename, width=250, height=250))
            Story.append(Spacer(1,12))
            
    # ✅ Batteria dettagliata
    Story.append(Spacer(1,12))
    Story.append(Paragraph(get_battery_info(), normal_style))         

    # 📄 Genera PDF
    doc.build(Story)

    # 🧹 Cleanup
    for img in ['cpu_usage.png', 'ram_usage.png'] + [f for f in os.listdir() if f.startswith('disk_usage_')]:
        if os.path.exists(img):
            os.remove(img)

# 🚀 Esegui
if __name__ == "__main__":
    output_filename = "system_checkup_report.pdf"
    generate_pdf_report(output_filename)
    print(f"✅ Report generato: {output_filename}")

