#!/usr/bin/env python3

import sys
import math
import random

try:
    import requests
except ImportError:
    print("Modulo requests non trovato. Se vedi questo messaggio, il venv non ha requests installato.")
    sys.exit(1)

def main():
    print("Ciao! Questo è uno script di test casuale.")
    print(f"Argomenti ricevuti: {sys.argv[1:]}")
    print(f"Radice quadrata di 16 calcolata con math: {math.sqrt(16)}")
    rand_num = random.randint(1, 100)
    print(f"Numero casuale da 1 a 100: {rand_num}")

    # Facciamo una richiesta http semplice a example.com
    try:
        r = requests.get("https://example.com")
        print(f"Richiesta a example.com status code: {r.status_code}")
    except Exception as e:
        print(f"Errore nella richiesta HTTP: {e}")

if __name__ == "__main__":
    main()
