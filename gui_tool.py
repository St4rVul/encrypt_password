#!/usr/bin/env python3
import customtkinter as ctk
import tkinter as tk
import threading
import time
from core_encryption import encrypt, decrypt

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window setup
        self.title("Advanced Encryption Tool")
        self.geometry("600x450")
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")
        self.minsize(500, 400)

        # Configure grid layout
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        # Create a header frame
        self.header_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.header_frame.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="ew")
        self.header_frame.grid_columnconfigure(0, weight=1)

        # App title
        self.title_label = ctk.CTkLabel(
            self.header_frame, 
            text="Password Encryption Tool", 
            font=ctk.CTkFont(size=24, weight="bold")
        )
        self.title_label.grid(row=0, column=0, sticky="w")

        # Create main content frame
        self.content_frame = ctk.CTkFrame(self)
        self.content_frame.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        self.content_frame.grid_columnconfigure(0, weight=1)

        # Input section
        self.input_label = ctk.CTkLabel(
            self.content_frame, 
            text="Input Data", 
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.input_label.grid(row=0, column=0, padx=10, pady=(10, 5), sticky="w")

        # Password/token entry with show/hide toggle
        self.password_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.password_frame.grid(row=1, column=0, padx=10, pady=5, sticky="ew")
        self.password_frame.grid_columnconfigure(0, weight=1)

        self.password_entry = ctk.CTkEntry(
            self.password_frame, 
            placeholder_text="Password or Token",
            height=35
        )
        self.password_entry.grid(row=0, column=0, sticky="ew")

        self.show_password = ctk.CTkButton(
            self.password_frame, 
            text="👁️",
            width=35, 
            height=35,
            command=self.toggle_password_visibility
        )
        self.show_password.grid(row=0, column=1, padx=(5, 0))
        self.password_visible = False

        # Keyphrase entry with show/hide toggle
        self.key_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.key_frame.grid(row=2, column=0, padx=10, pady=5, sticky="ew")
        self.key_frame.grid_columnconfigure(0, weight=1)

        self.key_entry = ctk.CTkEntry(
            self.key_frame, 
            placeholder_text="Keyphrase",
            show="●",
            height=35
        )
        self.key_entry.grid(row=0, column=0, sticky="ew")

        self.show_key = ctk.CTkButton(
            self.key_frame, 
            text="👁️",
            width=35, 
            height=35,
            command=self.toggle_key_visibility
        )
        self.show_key.grid(row=0, column=1, padx=(5, 0))
        self.key_visible = False

        # Algorithm selection
        self.algo_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.algo_frame.grid(row=3, column=0, padx=10, pady=5, sticky="ew")
        
        self.algo_label = ctk.CTkLabel(self.algo_frame, text="Algorithm:")
        self.algo_label.grid(row=0, column=0, padx=(0, 10))
        
        self.algorithm = ctk.StringVar(value="AES-256")
        self.algo_menu = ctk.CTkOptionMenu(
            self.algo_frame,
            values=["AES-256", "ChaCha20", "Fernet"],
            variable=self.algorithm
        )
        self.algo_menu.grid(row=0, column=1, sticky="w")

        # Result section
        self.result_label = ctk.CTkLabel(
            self, 
            text="Result", 
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.result_label.grid(row=2, column=0, padx=20, pady=(15, 5), sticky="w")

        self.result_frame = ctk.CTkFrame(self)
        self.result_frame.grid(row=3, column=0, padx=20, pady=(0, 10), sticky="nsew")
        self.result_frame.grid_columnconfigure(0, weight=1)
        self.result_frame.grid_rowconfigure(0, weight=1)

        self.result_textbox = ctk.CTkTextbox(self.result_frame)
        self.result_textbox.grid(row=0, column=0, padx=1, pady=1, sticky="nsew")

        # Action buttons section
        self.button_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.button_frame.grid(row=4, column=0, padx=20, pady=(10, 20), sticky="ew")
        self.button_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.encrypt_button = ctk.CTkButton(
            self.button_frame, 
            text="Encrypt", 
            command=self.encrypt_password,
            height=38,
            font=ctk.CTkFont(weight="bold")
        )
        self.encrypt_button.grid(row=0, column=0, padx=5)

        self.decrypt_button = ctk.CTkButton(
            self.button_frame, 
            text="Decrypt", 
            command=self.decrypt_token,
            height=38,
            font=ctk.CTkFont(weight="bold")
        )
        self.decrypt_button.grid(row=0, column=1, padx=5)

        self.copy_button = ctk.CTkButton(
            self.button_frame, 
            text="Copy Result", 
            command=self.copy_to_clipboard,
            height=38
        )
        self.copy_button.grid(row=0, column=2, padx=5)

        self.clear_button = ctk.CTkButton(
            self.button_frame, 
            text="Clear All", 
            command=self.clear_fields,
            height=38,
            fg_color="#555555",
            hover_color="#444444"
        )
        self.clear_button.grid(row=0, column=3, padx=5)

        # Status bar
        self.status_frame = ctk.CTkFrame(self, height=25)
        self.status_frame.grid(row=5, column=0, sticky="ew")
        self.status_frame.grid_columnconfigure(0, weight=1)
        
        self.status_label = ctk.CTkLabel(
            self.status_frame, 
            text="Ready", 
            anchor="w",
            font=ctk.CTkFont(size=12)
        )
        self.status_label.grid(row=0, column=0, padx=10, sticky="w")

        # Animation for clipboard copy
        self.copy_notification_visible = False

    def show_result(self, text):
        """Display text in the result textbox"""
        self.result_textbox.configure(state="normal")
        self.result_textbox.delete("1.0", "end")
        self.result_textbox.insert("1.0", text)
        self.result_textbox.configure(state="normal")  # Keep it enabled for selection

    def encrypt_password(self):
        """Encrypt the password and copy to clipboard"""
        password = self.password_entry.get()
        keyphrase = self.key_entry.get()
        algorithm = self.algorithm.get()

        if not password or not keyphrase:
            self.show_result("Error: Please provide both a password and a keyphrase.")
            self.update_status("Error: Missing input data", "error")
            return

        try:
            self.update_status("Encrypting...", "processing")
            # In a real implementation, you would pass the algorithm to your encryption function
            encrypted_token = encrypt(password, keyphrase)  
            self.show_result(f"Encrypted Token:\n\n{encrypted_token}")
            self.update_status("Encryption successful", "success")
            
            # Automatically copy to clipboard
            self.clipboard_clear()
            self.clipboard_append(encrypted_token)
            self.show_copy_notification()
        except Exception as e:
            self.show_result(f"Error:\n\n{str(e)}")
            self.update_status(f"Encryption failed: {str(e)}", "error")

    def decrypt_token(self):
        """Decrypt the token"""
        token = self.password_entry.get()
        keyphrase = self.key_entry.get()
        algorithm = self.algorithm.get()

        if not token or not keyphrase:
            self.show_result("Error: Please provide both a token and a keyphrase.")
            self.update_status("Error: Missing input data", "error")
            return

        try:
            self.update_status("Decrypting...", "processing")
            # In a real implementation, you would pass the algorithm to your decryption function
            decrypted_password = decrypt(token, keyphrase)
            self.show_result(f"Decrypted Password:\n\n{decrypted_password}")
            self.update_status("Decryption successful", "success")
        except Exception as e:
            self.show_result(f"Error:\n\n{str(e)}")
            self.update_status(f"Decryption failed: {str(e)}", "error")

    def toggle_password_visibility(self):
        """Toggle password visibility"""
        self.password_visible = not self.password_visible
        current_text = self.password_entry.get()
        self.password_entry.delete(0, "end")
        
        if self.password_visible:
            self.password_entry.configure(show="")
            self.show_password.configure(text="🔒")
        else:
            self.password_entry.configure(show="●")
            self.show_password.configure(text="👁️")
            
        self.password_entry.insert(0, current_text)

    def toggle_key_visibility(self):
        """Toggle key visibility"""
        self.key_visible = not self.key_visible
        current_text = self.key_entry.get()
        self.key_entry.delete(0, "end")
        
        if self.key_visible:
            self.key_entry.configure(show="")
            self.show_key.configure(text="🔒")
        else:
            self.key_entry.configure(show="●")
            self.show_key.configure(text="👁️")
            
        self.key_entry.insert(0, current_text)

    def copy_to_clipboard(self):
        """Copy result to clipboard using tkinter's clipboard functions"""
        result_text = self.result_textbox.get("1.0", "end-1c")
        if result_text:
            self.clipboard_clear()
            self.clipboard_append(result_text)
            self.show_copy_notification()

    def clear_fields(self):
        """Clear all input fields"""
        self.password_entry.delete(0, "end")
        self.key_entry.delete(0, "end")
        self.result_textbox.configure(state="normal")
        self.result_textbox.delete("1.0", "end")
        self.result_textbox.configure(state="normal")
        self.update_status("All fields cleared", "info")

    def update_status(self, message, status_type="info"):
        """Update status bar with message and appropriate color"""
        self.status_label.configure(text=message)
        
        if status_type == "error":
            self.status_frame.configure(fg_color="#541E1E")
        elif status_type == "success":
            self.status_frame.configure(fg_color="#1E5424")
        elif status_type == "processing":
            self.status_frame.configure(fg_color="#2C4770")
        else:  # info
            self.status_frame.configure(fg_color="#333333")

    def show_copy_notification(self):
        """Show a temporary notification that content was copied"""
        if self.copy_notification_visible:
            return
            
        self.copy_notification_visible = True
        notification = ctk.CTkFrame(self, corner_radius=10)
        
        # Position in bottom right of window
        self.update_idletasks()
        x = self.winfo_width() - 180
        y = self.winfo_height() - 100
        notification.place(x=x, y=y)
        
        ctk.CTkLabel(
            notification, 
            text="✓ Copied to clipboard",
            font=ctk.CTkFont(weight="bold"),
            padx=15,
            pady=10
        ).pack()
        
        # Auto-dismiss after 2 seconds
        def remove_notification():
            time.sleep(2)
            notification.destroy()
            self.copy_notification_visible = False
            
        threading.Thread(target=remove_notification, daemon=True).start()

if __name__ == "__main__":
    app = App()
    app.mainloop()
