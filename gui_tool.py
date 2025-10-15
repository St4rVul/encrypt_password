#!/usr/bin/env python3
import customtkinter as ctk
from core_encryption import encrypt, decrypt

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Encryption Tool")
        self.geometry("400x300")
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self.password_entry = ctk.CTkEntry(self, placeholder_text="Password or Token")
        self.password_entry.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="ew")

        self.key_entry = ctk.CTkEntry(self, placeholder_text="Keyphrase")
        self.key_entry.grid(row=1, column=0, padx=20, pady=10, sticky="ew")

        self.result_textbox = ctk.CTkTextbox(self, state="disabled")
        self.result_textbox.grid(row=2, column=0, padx=20, pady=10, sticky="nsew")

        self.encrypt_button = ctk.CTkButton(self, text="Encrypt", command=self.encrypt_password)
        self.encrypt_button.grid(row=3, column=0, padx=20, pady=(10, 5), sticky="ew")

        self.decrypt_button = ctk.CTkButton(self, text="Decrypt", command=self.decrypt_token)
        self.decrypt_button.grid(row=4, column=0, padx=20, pady=(5, 20), sticky="ew")

    def show_result(self, text):
        self.result_textbox.configure(state="normal")
        self.result_textbox.delete("1.0", "end")
        self.result_textbox.insert("1.0", text)
        self.result_textbox.configure(state="disabled")

    def encrypt_password(self):
        password = self.password_entry.get()
        keyphrase = self.key_entry.get()

        if not password or not keyphrase:
            self.show_result("Error: Please provide both a password and a keyphrase.")
            return

        try:
            encrypted_token = encrypt(password, keyphrase)
            self.show_result(f"Encrypted Token:\n\n{encrypted_token}")
        except Exception as e:
            self.show_result(f"Error:\n\n{e}")

    def decrypt_token(self):
        token = self.password_entry.get()
        keyphrase = self.key_entry.get()

        if not token or not keyphrase:
            self.show_result("Error: Please provide both a token and a keyphrase.")
            return

        try:
            decrypted_password = decrypt(token, keyphrase)
            self.show_result(f"Decrypted Password:\n\n{decrypted_password}")
        except Exception as e:
            self.show_result(f"Error:\n\n{e}")

if __name__ == "__main__":
    app = App()
    app.mainloop()
