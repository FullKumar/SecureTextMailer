# SecureTextMailer

SecureText Mailer is a simple desktop app where you can write a message, lock it with a password (encrypt), unlock it (decrypt), and also send it by email.  
It is made with Python using Tkinter for the window, and Gmail SMTP for sending mail.

# Features
- You can lock (encrypt) and unlock (decrypt) messages safely  
- Password becomes stronger with PBKDF2 (extra protection)  
- Send secret messages by Gmail in a safe way (SSL)  
- Open (decrypt) received emails with the same password  
- Very simple window app, easy for anyone to use 

Extra safety:
- Shows error if wrong password is used
  
# What you need
- Python 3.8 or newer
- cryptography library  
(Tkinter, smtplib, ssl, base64 are already in Python)

# Gmail setup
- Go to Google Account
- Create an App Password
- Use this App Password instead of your real Gmail password

# How to install
1. Download This Simple project from github.
2. Run the app: open CMD, type  python securetext_mailer.py

# Steps:
- Write your message
- Enter a secret key (password)
- Press Encrypt to lock or Decrypt to unlock

To send mail:
- Write To Address, Subject, Gmail address and App Password
- (Tick "Encrypt before sending" if you want automatic encryption)
- Press Send Email

 # APP UI
![App working](https://raw.githubusercontent.com/FullKumar/SecureTextMailer/main/worksfollows.jpg)

# Security Notes
- Always use a strong password.
- This tool is meant for personal / educational use.
- Not recommended for high-security corporate or military use without audits.
