import tkinter as tk
from tkinter import ttk, messagebox, filedialog

class BoforaCipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Modified Bofora Cipher Application")

        # Interface setup
        self.setup_ui()

    def setup_ui(self):
        frame = ttk.Frame(self.root, padding="10")
        frame.grid(row=0, column=0, sticky="NSEW")

        # Text input from file
        ttk.Label(frame, text="Text File:").grid(row=0, column=0, sticky="W")
        self.text_file_entry = ttk.Entry(frame, width=50)
        self.text_file_entry.grid(row=0, column=1, sticky="W")
        ttk.Button(frame, text="Browse", command=self.load_text_file).grid(row=0, column=2)

        # Key input
        ttk.Label(frame, text="Key File:").grid(row=1, column=0, sticky="W")
        self.key_file_entry = ttk.Entry(frame, width=50)
        self.key_file_entry.grid(row=1, column=1, sticky="W")
        ttk.Button(frame, text="Browse", command=self.load_key_file).grid(row=1, column=2)

        # Text input area for manual entry
        ttk.Label(frame, text="Or Enter Text Manually:").grid(row=2, column=0, sticky="W", columnspan=3)
        self.manual_text_entry = tk.Text(frame, width=80, height=5)
        self.manual_text_entry.grid(row=3, column=0, columnspan=3, pady=5)

        # Buttons for encryption and decryption
        ttk.Button(frame, text="Encrypt (Modified Bofora)", command=self.encrypt_modified_bofora).grid(row=4, column=0, pady=10)
        ttk.Button(frame, text="Decrypt (Modified Bofora)", command=self.decrypt_modified_bofora).grid(row=4, column=1, pady=10)

        # Output text area
        self.result_text = tk.Text(frame, width=80, height=15)
        self.result_text.grid(row=5, column=0, columnspan=3, pady=10)

    def load_text_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if file_path:
            self.text_file_entry.delete(0, tk.END)
            self.text_file_entry.insert(0, file_path)

    def load_key_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if file_path:
            self.key_file_entry.delete(0, tk.END)
            self.key_file_entry.insert(0, file_path)

    def read_file(self, file_path):
        with open(file_path, 'r', encoding='utf-8') as file:
            return file.read()

    def write_file(self, file_path, content):
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(content)

    def encrypt_modified_bofora(self):
        self.process_bofora(encrypt=True)

    def decrypt_modified_bofora(self):
        self.process_bofora(encrypt=False)

    def process_bofora(self, encrypt):
        text = self.get_text_input()
        key_file = self.key_file_entry.get()

        if not text or not key_file:
            messagebox.showerror("Error", "Please provide text and key file.")
            return

        key = self.read_file(key_file)

        if encrypt:
            processed_text = self.bofora_encrypt(text, key)
            self.write_file("encrypted_text.txt", processed_text)
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, "Encrypted text saved to 'encrypted_text.txt'.\n")
            self.result_text.insert(tk.END, "Encrypted Content:\n" + processed_text + "\n")
        else:
            processed_text = self.bofora_decrypt(text, key)
            self.write_file("decrypted_text.txt", processed_text)
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, "Decrypted text saved to 'decrypted_text.txt'.\n")
            self.result_text.insert(tk.END, "Decrypted Content:\n" + processed_text + "\n")

    def get_text_input(self):
        file_path = self.text_file_entry.get()
        if file_path:
            return self.read_file(file_path)
        else:
            return self.manual_text_entry.get("1.0", tk.END).strip()

    def bofora_encrypt(self, text, key):
        X = 256  # Size of the alphabet (ASCII)
        key_repeated = self.prepare_key(text, key)
        encrypted_text = []

        for m, k in zip(text, key_repeated):
            if m == '_':
                encrypted_text.append('_')
                continue
            c = (ord(m) - ord(k)) % X
            encrypted_text.append(chr(c))

        return ''.join(encrypted_text)

    def bofora_decrypt(self, text, key):
        X = 256  # Size of the alphabet (ASCII)
        key_repeated = self.prepare_key(text, key)
        decrypted_text = []

        for c, k in zip(text, key_repeated):
            if c == '_':
                decrypted_text.append('_')
                continue
            m = (ord(c) + ord(k)) % X
            decrypted_text.append(chr(m))

        return ''.join(decrypted_text)

    def prepare_key(self, text, key):
        key_repeated = []
        j = 0

        for i in range(len(text)):
            if text[i] == '_':
                key_repeated.append('_')
            else:
                key_repeated.append(key[j % len(key)])
                j += 1

        return ''.join(key_repeated)

# Main execution
if __name__ == "__main__":
    root = tk.Tk()
    app = BoforaCipherApp(root)
    root.mainloop()
