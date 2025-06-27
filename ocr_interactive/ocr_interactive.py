import sys
import os
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
