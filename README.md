# Flask Encryption App

A lightweight Flask web app for **user-based text encryption/decryption** with password strength checking, custom cipher keys, and session-based authentication.

Built for learning crypto basics, Flask auth, and clean backend logic.

---

## ✨ Features

- User **signup / login / logout** (session-based)
- **Password strength checker** (Very Weak → Very Strong)
- Passwords stored using a **custom deterministic encryption**
- Built-in **ROT13 cipher**
- **Custom shift cipher keys** (digit-based patterns like `123`)
- Per-user key storage
- Encrypt & decrypt messages via API
- Simple file-based persistence (`users.txt`, `keys.txt`)

---

## How It Works (High Level)

- Password strength is scored using length, case, digits, and symbols
- Passwords are encrypted using a printable-character mapping + prime offsets
- Each user has their own encryption keys
- ROT13 is always available by default
- Custom keys apply variable Caesar shifts per character

---

## 🛠 Tech Stack

- **Python**
- **Flask**
- **Flask-CORS**
- File-based JSON storage
- Vanilla HTML/CSS/JS frontend (served from `static/`)

---


---

## 🚀 Setup & Run

```bash
pip install -r requirements.txt

python app.py
```



