# 🔐 Vaultmate — CLI Password Manager (Python)

A lightweight, encrypted command-line password manager for personal use.  
Vaultmate stores credentials in an **encrypted CSV** (Fernet/AES) with a **random per-vault salt** and strong **PBKDF2-HMAC (SHA-256)** key derivation (default **1,200,000** iterations).

---

## ✨ Highlights

- **End-to-end encryption** (Fernet/AES + PBKDF2-HMAC)
- **Random 16-byte salt** generated automatically for each new vault
- **Search** across Name / Email / Username / Notes (case-insensitive)
- **Details view** from list (password **masked**)
- **Immediate save after delete** (prevents accidental data loss)
- **Master password input is hidden + trimmed** (avoids trailing-space mistakes)
- **Password generator** with strength rating & compromised-list check
- **Local-only**, portable, simple terminal UI
- Timestamps for **creation** and **last modification**
- Basic tests with **pytest**

> Optional (supported in code/config):
> - Cryptographically secure password generation via `secrets`
> - `PWM_KDF_ITERATIONS` env var to tune PBKDF2 cost
> - Paths anchored to project directory for robustness

---

## 📦 Requirements

- Python **3.10+**
- `cryptography`
- `pytest` (for tests)

Install from `requirements.txt`:
```bash
pip install -r requirements.txt
```

---

## 🚀 Quickstart

1. **Create & activate a virtual environment**
   ```bash
   python -m venv venv
   # Windows:
   venv\Scripts\activate
   # macOS/Linux:
   # source venv/bin/activate
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the app**
   ```bash
   python cli_password_manager.py
   ```

On first run you’ll see:
- **[1] Open a new file** — creates a new encrypted vault in `./resources/`
- **[2] Open an existing file** — decrypts a vault (enter master password)

**Main Menu**
- **[1] See all entries** → pick a number to view details (password masked)  
- **[2] Search** → search by name/email/username/notes  
- **[3] Add** / **[4] Update** / **[5] Delete** / **[6] Exit (save & encrypt)**

---

## 🗂️ Data Model (per entry)

- **Name**
- **Email**
- **Username**
- **Password** *(encrypted at rest)*
- **Notes**
- **Creation** (timestamp)
- **Modified** (timestamp)

Vault artifacts live in `./resources/`:
- `myvault.csv` (encrypted content)
- `myvault.csv.salt` (16-byte random salt)

> ⚠️ **Never commit vault files** to Git. See `.gitignore` below.

---

## 🔐 Security Notes

- Uses **Fernet** (AES-CBC + HMAC) for encryption and integrity
- **PBKDF2-HMAC (SHA-256)** for key derivation (default **1,200,000** iterations)
- Fresh **random 16-byte salt** generated when creating a new vault
- Master password input uses **getpass** and is **trimmed** to prevent mistakes
- Same plaintext password → **different ciphertexts** across vaults due to distinct salts

**Config:**
```text
PWM_KDF_ITERATIONS   # optional, override PBKDF2 iterations (int)
```

Your security ultimately depends on your **master password strength**. Choose a strong one and keep it safe.

---

## 🧪 Testing

```bash
pytest -q
```

---

## 📁 Project Structure

```
.
├─ cli_password_manager.py        # main app
├─ requirements.txt
├─ README.md
├─ LICENSE
├─ data/
│  └─ compromised_list.txt        # used by strength check
├─ resources/
│  └─ .gitkeep                    # vaults are created here (not committed)
└─ test_cli_password_manager.py   # basic tests
```

---

## 🗺️ Roadmap

- Clipboard copy with **auto-clear** (e.g., 20s)
- Command-line flags for headless operations
- Optional SQLite backend
- Best-effort secure memory cleanup on exit

---

## ⚖️ License

MIT — see `LICENSE`.

---

## 🙌 Acknowledgments

Thanks to the Python and security communities for references used while designing and hardening this tool.

---

### `.gitignore` (add this as a separate file named `.gitignore`)

```
venv/
__pycache__/
*.pyc
.env
resources/*.csv
resources/*.csv.salt
```
