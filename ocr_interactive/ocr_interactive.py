import sys
import os
import subprocess
import platform
from PIL import Image
import pytesseract
from colorama import Fore, Style, init
from InquirerPy import inquirer

init(autoreset=True)  # Colori automatici reset

def print_info(msg):
    print(Fore.CYAN + msg + Style.RESET_ALL)

def print_error(msg):
    print(Fore.RED + msg + Style.RESET_ALL)

def print_success(msg):
    print(Fore.GREEN + msg + Style.RESET_ALL)

def is_tesseract_installed():
    """Controlla se tesseract è installato nel sistema."""
    try:
        subprocess.run(['tesseract', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def install_tesseract():
    """Prova a installare tesseract in base al SO rilevato."""
    system = platform.system()
    print_info(f"Sistema operativo rilevato: {system}")

    if system == "Linux":
        # Proviamo a identificare distro per package manager
        try:
            with open('/etc/os-release') as f:
                info = f.read().lower()
            if 'arch' in info:
                pm = 'pacman'
                cmd = ['sudo', 'pacman', '-S', '--noconfirm', 'tesseract', 'tesseract-data-eng', 'tesseract-data-ita']
            elif any(x in info for x in ['debian', 'ubuntu', 'mint']):
                pm = 'apt'
                print_info("Aggiornamento repository con apt...")
                subprocess.run(['sudo', 'apt', 'update'], check=True)
                cmd = ['sudo', 'apt', 'install', '-y', 'tesseract-ocr', 'tesseract-ocr-eng', 'tesseract-ocr-ita']
            else:
                print_error("Distro Linux non riconosciuta automaticamente per installazione automatica.")
                return False
        except Exception as e:
            print_error(f"Errore nel riconoscere la distro: {e}")
            return False

    elif system == "Darwin":
        pm = 'brew'
        cmd = ['brew', 'install', 'tesseract']

    elif system == "Windows":
        # Windows: proviamo scoop o chocolatey
        try:
            subprocess.run(['scoop', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            pm = 'scoop'
            cmd = ['scoop', 'install', 'tesseract']
        except Exception:
            try:
                subprocess.run(['choco', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                pm = 'choco'
                cmd = ['choco', 'install', 'tesseract', '-y']
            except Exception:
                print_error("Non è stato possibile trovare un package manager automatico per Windows (scoop/choco).")
                print_error("Per favore installa Tesseract manualmente da https://github.com/tesseract-ocr/tesseract/releases")
                return False
    else:
        print_error(f"Sistema operativo {system} non supportato per installazione automatica.")
        return False

    print_info(f"Installerò tesseract usando {pm}. Confermi? (y/n)")
    answer = input().lower()
    if answer == 'y':
        try:
            print_info(f"Sto eseguendo: {' '.join(cmd)}")
            subprocess.run(cmd, check=True)
            print_success("Installazione completata. Riprova ad avviare lo script.")
            return True
        except subprocess.CalledProcessError as e:
            print_error(f"Errore durante l'installazione: {e}")
            return False
    else:
        print_error("Installazione tesseract annullata dall'utente.")
        return False

def list_image_files(folder='.'):
    exts = ('.png', '.jpg', '.jpeg', '.bmp', '.tiff')
    files = [f for f in os.listdir(folder) if f.lower().endswith(exts) and os.path.isfile(f)]
    return files

def select_file_interactive():
    files = list_image_files()
    if not files:
        print_error("Nessun file immagine trovato nella cartella corrente.")
        sys.exit(1)
    print_info("Seleziona un file immagine con le freccette e premi Invio:")
    choice = inquirer.select(
        message="File immagine:",
        choices=files,
        default=files[0],
        cycle=True
    ).execute()
    return choice

def main():
    # Controllo tesseract come primissima cosa
    if not is_tesseract_installed():
        print_error("Tesseract non è installato sul sistema.")
        if not install_tesseract():
            print_error("Impossibile procedere senza tesseract. Esco.")
            sys.exit(1)
        else:
            sys.exit(0)  # Esci dopo installazione, utente deve rilanciare lo script

    if len(sys.argv) > 1:
        image_path = sys.argv[1]
        if not os.path.isfile(image_path):
            print_error(f"Il file '{image_path}' non esiste!")
            sys.exit(1)
    else:
        image_path = select_file_interactive()

    print_info(f"Caricamento immagine: {image_path}")
    try:
        img = Image.open(image_path)
    except Exception as e:
        print_error(f"Errore nell'aprire l'immagine: {e}")
        sys.exit(1)

    print_info("Eseguo OCR (lingua italiana)...")
    try:
        text = pytesseract.image_to_string(img, lang='ita')
    except Exception as e:
        print_error(f"Errore durante OCR: {e}")
        sys.exit(1)

    if text.strip():
        print_success("\nTesto estratto:")
        print(text)
    else:
        print_error("Non è stato possibile estrarre testo dall'immagine.")

if __name__ == '__main__':
    main()
