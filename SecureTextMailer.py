#!/usr/bin/env python3
import base64
import os
import smtplib
import ssl
import sys
import tkinter as tk
from email.message import EmailMessage
from tkinter import messagebox

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

APP_NAME = "SecureText Mailer"
UI_SECRET = "1234"  
MAGIC = b"STM1"      

def resource_path(rel_path: str) -> str:
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, rel_path)
    return os.path.join(os.path.abspath("."), rel_path)

def show_result_window(title: str, content: str, bg="#00bd56"):
    win = tk.Toplevel(root)
    win.title(title)
    win.geometry("420x220")
    win.configure(bg=bg)

    tk.Label(win, text=title.upper(), font=("Arial", 14, "bold"), fg="white", bg=bg).place(x=10, y=5)
    txt = tk.Text(win, font=("Arial", 10), bg="white", relief=tk.GROOVE, wrap=tk.WORD, bd=0)
    txt.place(x=10, y=40, width=400, height=160)
    txt.insert(tk.END, content)

def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    return kdf.derive(password.encode("utf-8"))

def do_encrypt_text(raw: str, password: str) -> str:
  
    if not password:
        raise ValueError("Password required for encryption")
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, raw.encode("utf-8"), None)
    blob = base64.b64encode(MAGIC + salt + nonce + ct).decode("ascii")
    return blob

def do_decrypt_text(blob_b64: str, password: str) -> str:
   
    if not password:
        raise ValueError("Password required for decryption")
    try:
        data = base64.b64decode(blob_b64.encode("ascii"))
    except Exception:
        raise ValueError("Input is not valid base64")
    if len(data) < len(MAGIC) + 16 + 12:
        raise ValueError("Ciphertext too short or invalid")
    if data[:len(MAGIC)] != MAGIC:
        raise ValueError("Not a SecureText (STM1) encrypted message")

    salt = data[len(MAGIC):len(MAGIC)+16]
    nonce = data[len(MAGIC)+16:len(MAGIC)+16+12]
    ct = data[len(MAGIC)+28:]

    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        pt = aesgcm.decrypt(nonce, ct, None)
    except Exception:
        raise ValueError("Wrong password or message corrupted")
    return pt.decode("utf-8")

def _looks_encrypted_blob(s: str) -> bool:
   
    try:
        d = base64.b64decode(s.encode("ascii"))
        return len(d) >= len(MAGIC) + 28 and d.startswith(MAGIC)
    except Exception:
        return False

def encrypt():
    pwd = code_var.get().strip()
    if pwd == "":
        messagebox.showerror("Encryption", "Input Password")
        return
    message = text_input.get("1.0", tk.END).rstrip("\n")
    if not message:
        messagebox.showwarning("Encryption", "Nothing to encrypt")
        return
    try:
        enc = do_encrypt_text(message, pwd)
        show_result_window("Encryption", enc, "#ed3833")
        last_result_var.set(enc)
    except Exception as e:
        messagebox.showerror("Encryption", f"Failed to encrypt: {e}")

def decrypt():
    pwd = code_var.get().strip()
    if pwd == "":
        messagebox.showerror("Decryption", "Input Password")
        return
    message = text_input.get("1.0", tk.END).rstrip("\n")
    if not message:
        messagebox.showwarning("Decryption", "Nothing to decrypt")
        return
    try:
        dec = do_decrypt_text(message, pwd)
        show_result_window("Decryption", dec, "#00bd56")
        last_result_var.set(dec)
    except Exception as e:
    
        msg = str(e)
        if "Wrong password" in msg or "corrupted" in msg:
            messagebox.showerror("Decryption", "Wrong password or corrupted message.")
        else:
            messagebox.showerror("Decryption", f"Failed to decrypt: {e}")

def reset():
    code_var.set("")  
    text_input.delete("1.0", tk.END)
    email_to_var.set("")
    email_subj_var.set("")

    smtp_user_var.set(os.getenv("SMTP_USER", ""))
    smtp_pass_var.set(os.getenv("SMTP_PASS", ""))
    encrypt_before_send_var.set(True)
    last_result_var.set("")

def send_email():

    to_addr = email_to_var.get().strip()
    subject = email_subj_var.get().strip()
    smtp_user = smtp_user_var.get().strip() or os.getenv("SMTP_USER", "")
    smtp_pass = smtp_pass_var.get().strip() or os.getenv("SMTP_PASS", "")

    if not to_addr:
        messagebox.showerror("Email", "Receiver email (To) is required")
        return
    if not subject:
        messagebox.showerror("Email", "Subject is required")
        return
    if not smtp_user or not smtp_pass:
        messagebox.showerror(
            "Email",
            "Missing sender Gmail or App Password.\n\n"
            "Fill the 'From (Gmail)' and 'App Password' fields, or set SMTP_USER/SMTP_PASS env vars."
        )
        return

    base_text = last_result_var.get().strip()
    if not base_text:
        base_text = text_input.get("1.0", tk.END).rstrip("\n")
    if not base_text:
        messagebox.showwarning("Email", "Nothing to send")
        return

    try:
        body = base_text
        if encrypt_before_send_var.get():
            pwd = code_var.get().strip()
            if not pwd:
                messagebox.showerror("Email", "Enter a password to encrypt before sending.")
                return
           
            if not _looks_encrypted_blob(base_text):
                body = do_encrypt_text(base_text, pwd)

        msg = EmailMessage()
        msg["From"] = smtp_user
        msg["To"] = to_addr
        msg["Subject"] = subject
        msg.set_content(body)

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)

        messagebox.showinfo("Email", "Email sent successfully!")
    except Exception as e:
        messagebox.showerror("Email", f"Failed to send email:\n{e}")

def build_ui():
    global root, code_var, text_input, email_to_var, email_subj_var
    global encrypt_before_send_var, last_result_var, smtp_user_var, smtp_pass_var

    root = tk.Tk()
    root.geometry("420x640")
    root.title(SecureTextMailer)

    try:
        icon_path = resource_path("keys.png")
        if os.path.exists(icon_path):
            icon = tk.PhotoImage(file=icon_path)
            root.iconphoto(False, icon)
    except Exception:
        pass

    tk.Label(root, text="Enter text for encryption and decryption", fg="black", font=("Calibri", 13)).place(x=10, y=10)

    text_input = tk.Text(root, font=("Arial", 12), bg="white", relief=tk.GROOVE, wrap=tk.WORD, bd=0)
    text_input.place(x=10, y=40, width=395, height=140)

    tk.Label(root, text="Enter secret key (used for AES‑GCM)", fg="black", font=("Calibri", 13)).place(x=10, y=190)

    code_var = tk.StringVar()
    tk.Entry(root, textvariable=code_var, width=19, bd=0, font=("Arial", 20), show="*").place(x=10, y=215)

    tk.Button(root, text="ENCRYPT", height=2, width=20, bg="#ed3833", fg="white", bd=0, command=encrypt).place(x=10, y=260)
    tk.Button(root, text="DECRYPT", height=2, width=20, bg="#00bd56", fg="white", bd=0, command=decrypt).place(x=210, y=260)

    tk.Label(root, text="Email (To)", fg="black", font=("Calibri", 12)).place(x=10, y=310)
    email_to_var = tk.StringVar()
    tk.Entry(root, textvariable=email_to_var, width=35, bd=0, font=("Arial", 12)).place(x=10, y=330)

    tk.Label(root, text="Subject", fg="black", font=("Calibri", 12)).place(x=10, y=360)
    email_subj_var = tk.StringVar()
    tk.Entry(root, textvariable=email_subj_var, width=35, bd=0, font=("Arial", 12)).place(x=10, y=380)

    tk.Label(root, text="From (Gmail)", fg="black", font=("Calibri", 12)).place(x=10, y=410)
    smtp_user_var = tk.StringVar(value=os.getenv("SMTP_USER", ""))
    tk.Entry(root, textvariable=smtp_user_var, width=35, bd=0, font=("Arial", 12)).place(x=10, y=430)

    tk.Label(root, text="App Password", fg="black", font=("Calibri", 12)).place(x=10, y=460)
    smtp_pass_var = tk.StringVar(value=os.getenv("SMTP_PASS", ""))
    tk.Entry(root, textvariable=smtp_pass_var, width=35, bd=0, font=("Arial", 12), show="*").place(x=10, y=480)

    encrypt_before_send_var = tk.BooleanVar(value=True)
    tk.Checkbutton(root, text="Encrypt before sending", variable=encrypt_before_send_var, onvalue=True, offvalue=False).place(x=10, y=510)

    tk.Button(root, text="SEND EMAIL", height=2, width=35, bg="#6a5acd", fg="white", bd=0, command=send_email).place(x=10, y=540)

    tk.Button(root, text="RESET", height=2, width=35, bg="#1089ff", fg="white", bd=0, command=reset).place(x=10, y=580)

    last_result_var = tk.StringVar()
    return root

def main():
    build_ui()
    reset()
    root.mainloop()

if __name__ == "__main__":
    main()
