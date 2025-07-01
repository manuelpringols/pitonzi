import psutil
import platform
import matplotlib.pyplot as plt
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
import datetime
import os

# ✅ Funzione: genera grafico dell'uso CPU
def generate_cpu_chart():
    cpu_percentages = psutil.cpu_percent(percpu=True, interval=1)
    cores = [f'Core {i}' for i in range(len(cpu_percentages))]

    plt.figure(figsize=(10,5))
    bars = plt.bar(cores, cpu_percentages, color='teal')
    plt.ylabel('Utilizzo (%)')
    plt.title('Utilizzo CPU per core')

    # Colora le barre in base al carico
    for bar, percent in zip(bars, cpu_percentages):
        if percent > 80:
            bar.set_color('red')
        elif percent > 50:
            bar.set_color('orange')
    
    plt.tight_layout()
    plt.savefig('cpu_usage.png')
    plt.close()

# ✅ Funzione: genera grafico uso RAM
def generate_ram_chart():
    ram = psutil.virtual_memory()
    labels = ['Usata', 'Libera']
    sizes = [ram.used, ram.available]
    colors_pie = ['purple', 'lightgreen']

    plt.figure(figsize=(6,6))
    plt.pie(sizes, labels=labels, colors=colors_pie, autopct='%1.1f%%')
    plt.title('Utilizzo RAM')
    plt.savefig('ram_usage.png')
    plt.close()

# ✅ Funzione: genera report PDF
def generate_pdf_report(filename):
    doc = SimpleDocTemplate(filename, pagesize=A4)
    styles = getSampleStyleSheet()
    Story = []

    # Titolo
    Story.append(Paragraph("🖥️ System Checkup Report", styles['Title']))
    Story.append(Spacer(1,12))

    # Info sistema
    uname = platform.uname()
    Story.append(Paragraph(f"<b>Nome Sistema:</b> {uname.system}", styles['Normal']))
    Story.append(Paragraph(f"<b>Nome Nodo:</b> {uname.node}", styles['Normal']))
    Story.append(Paragraph(f"<b>Versione:</b> {uname.version}", styles['Normal']))
    Story.append(Paragraph(f"<b>Macchina:</b> {uname.machine}", styles['Normal']))
    Story.append(Paragraph(f"<b>Processore:</b> {uname.processor}", styles['Normal']))
    Story.append(Spacer(1,12))

    # Data e ora
    now = datetime.datetime.now()
    Story.append(Paragraph(f"<b>Data report:</b> {now.strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    Story.append(Spacer(1,12))

    # Grafici CPU e RAM
    generate_cpu_chart()
    generate_ram_chart()

    Story.append(Paragraph("<b>Utilizzo CPU</b>", styles['Heading2']))
    Story.append(Image('cpu_usage.png', width=400, height=200))
    Story.append(Spacer(1,12))

    Story.append(Paragraph("<b>Utilizzo RAM</b>", styles['Heading2']))
    Story.append(Image('ram_usage.png', width=300, height=300))
    Story.append(Spacer(1,12))

    # Disco
    Story.append(Paragraph("<b>Spazio Disco</b>", styles['Heading2']))
    partitions = psutil.disk_partitions()
    for p in partitions:
        usage = psutil.disk_usage(p.mountpoint)
        Story.append(Paragraph(f"{p.device} ({p.mountpoint}) - {usage.percent}% usato ({get_size(usage.used)} / {get_size(usage.total)})", styles['Normal']))
    Story.append(Spacer(1,12))

    # Genera PDF
    doc.build(Story)

    # Cleanup immagini temporanee
    os.remove('cpu_usage.png')
    os.remove('ram_usage.png')

# ✅ Funzione helper: formatta dimensioni file
def get_size(bytes, suffix="B"):
    factor = 1024
    for unit in ["","K","M","G","T","P"]:
        if bytes < factor:
            return f"{bytes:.2f}{unit}{suffix}"
        bytes /= factor

# 🚀 Esegui
if __name__ == "__main__":
    output_filename = "system_checkup_report.pdf"
    generate_pdf_report(output_filename)
    print(f"✅ Report generato: {output_filename}")
