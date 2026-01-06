import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import hashlib
import threading
import time

# ---------------------------------------------------------
# Hash a word using the selected algorithm
# ---------------------------------------------------------
def hash_word(word, algo):
    if algo == "MD5":
        return hashlib.md5(word.encode()).hexdigest()
    elif algo == "SHA-1":
        return hashlib.sha1(word.encode()).hexdigest()
    elif algo == "SHA-256":
        return hashlib.sha256(word.encode()).hexdigest()
    else:
        return None

# ---------------------------------------------------------
# Dictionary Attack Simulation (safe)
# ---------------------------------------------------------
def start_attack():
    t = threading.Thread(target=dictionary_attack)
    t.start()

def dictionary_attack():
    output_box.delete(1.0, tk.END)

    target_hash = target_hash_entry.get().strip()
    algo = algo_var.get()
    wordlist_path = wordlist_path_var.get()

    # Input checks
    if not target_hash:
        messagebox.showerror("Error", "Enter a target hash.")
        return

    if not wordlist_path:
        messagebox.showerror("Error", "Select a wordlist file.")
        return

    output_box.insert(tk.END, f"[*] Starting Dictionary Attack ({algo})...\n\n")

    try:
        with open(wordlist_path, "r", errors="ignore") as f:
            for word in f:
                word = word.strip()
                if not word:
                    continue

                # Hash the word
                hashed_word = hash_word(word, algo)

                output_box.insert(tk.END, f"Trying: {word}\n")
                output_box.see(tk.END)

                time.sleep(0.05)  # Slow for demo

                # Compare with target hash
                if hashed_word == target_hash:
                    output_box.insert(tk.END, f"\n[+] Password FOUND: {word}\n")
                    return

    except Exception as e:
        output_box.insert(tk.END, f"[!] Error: {e}\n")
        return

    output_box.insert(tk.END, "\n[-] Password NOT found in wordlist.\n")

# ---------------------------------------------------------
# Load wordlist file
# ---------------------------------------------------------
def load_wordlist():
    path = filedialog.askopenfilename(
        title="Select Wordlist File",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    if path:
        wordlist_path_var.set(path)

# ---------------------------------------------------------
# GUI SETUP
# ---------------------------------------------------------
root = tk.Tk()
root.title("PyCyberSuite Dictionary Attack Tool (Safe)")
NEON = "#26ff00"
BG = "#000"
root.configure(bg=BG)


tk.Label(root, fg=NEON, bg=BG,text="Target Hash:").pack(pady=3)
target_hash_entry = tk.Entry(root, width=60)
target_hash_entry.pack()

tk.Label(root,fg=NEON, bg=BG, text="Hash Algorithm:").pack(pady=3)
algo_var = tk.StringVar(value="SHA-256")
algo_menu = tk.OptionMenu(root, algo_var, "MD5", "SHA-1", "SHA-256")
algo_menu.pack()

tk.Label(root, fg=NEON, bg=BG,text="Wordlist File:").pack(pady=3)
wordlist_path_var = tk.StringVar()
tk.Entry(root,fg=NEON, bg=BG, textvariable=wordlist_path_var, width=50).pack()
tk.Button(root,fg=NEON, bg=BG, text="Browse", command=load_wordlist).pack(pady=5)

tk.Button(root,fg=NEON, bg=BG, text="Start Dictionary Attack", command=start_attack).pack(pady=10)

output_box = scrolledtext.ScrolledText(root,fg=NEON, bg=BG, width=70, height=20)
output_box.pack(pady=5)

root.mainloop()

import hashlib
print(hashlib.sha256("Ravi@123#".encode()).hexdigest())
