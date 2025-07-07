import sys
import queue
import sounddevice as sd
from vosk import Model, KaldiRecognizer

model = Model("model")  # scarica il modello vosk adatto (es. small o base)
rec = KaldiRecognizer(model, 16000)
q = queue.Queue()

def audio_callback(indata, frames, time, status):
    q.put(bytes(indata))

with sd.RawInputStream(samplerate=16000, blocksize=8000, dtype='int16',
                       channels=1, callback=audio_callback):
    print("Parla e vedrai il testo trascritto in tempo reale. Di' 'enter' per eseguire.")
    buffer = ""
    while True:
        data = q.get()
        if rec.AcceptWaveform(data):
            result = rec.Result()
            text = eval(result)['text']
            print(f"\r{text}", end="")
            if "enter" in text or "esegui" in text:
                print(f"\nEseguo comando: {buffer}")
                import os
                os.system(buffer)
                buffer = ""
            else:
                buffer += " " + text
        else:
            partial = rec.PartialResult()
            partial_text = eval(partial)['partial']
            print(f"\r{buffer} {partial_text}", end="")
