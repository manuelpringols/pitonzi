import sounddevice as sd
import numpy as np
import webrtcvad
import whisper
import collections
import sys
import os
import tempfile
import scipy.io.wavfile

# Initialize whisper
model = whisper.load_model("base")

# Initialize VAD
vad = webrtcvad.Vad(1)  # Aggressiveness: 0-3

samplerate = 16000
frame_duration = 30  # ms
frame_size = int(samplerate * frame_duration / 1000)

def record_until_silence(max_silence_ms=1000):
    print("🎙️ Start talking...")
    audio_buffer = []
    silence_buffer = 0

    stream = sd.InputStream(channels=1, samplerate=samplerate, dtype='int16')
    stream.start()

    try:
        while True:
            data, _ = stream.read(frame_size)
            frame = data.flatten().tobytes()
            is_speech = vad.is_speech(frame, samplerate)

            audio_buffer.append(data)

            if is_speech:
                silence_buffer = 0
            else:
                silence_buffer += frame_duration

            if silence_buffer > max_silence_ms:
                break

    finally:
        stream.stop()

    # Concatenate all frames
    audio_np = np.concatenate(audio_buffer, axis=0)
    return audio_np

def save_wav(audio, filename):
    scipy.io.wavfile.write(filename, samplerate, audio)

buffer = ""

while True:
    audio = record_until_silence(max_silence_ms=800)  # stop after 0.8s of silence
    with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
        save_wav(audio, f.name)
        result = model.transcribe(f.name, language='it')
        text = result["text"].lower().strip()
        os.unlink(f.name)

    print(f"🗣️ Heard: {text}")

    if "enter" in text or "esegui" in text:
        if buffer.strip():
            print(f"🚀 Executing: {buffer.strip()}")
            subprocess.run(buffer.strip(), shell=True)
            buffer = ""
        else:
            print("⚠️ No command to execute.")
    else:
        buffer += " " + text
        print(f"💬 Current buffer: {buffer.strip()}")
