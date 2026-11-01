# CwayPro

> Developer CLI companion tool and server-rendered web dashboard for syncing local code, tracking terminal flags, and safeguarding credentials with authenticated AES encryption.

---

## 🚀 Tech Stack

- **Framework**: Django 6.1 (Python 3.14)
- **Database**: PostgreSQL (psycopg 3)
- **Security & Crypto**: `cryptography` (Fernet AES-128-CBC + HMAC-SHA256)
- **Authentication**: `django-allauth` (Google & GitHub OAuth) + Personal Access Tokens (`APIToken`)
- **Frontend**: Server-rendered Django Templates with Gruvbox Hard Dark aesthetic
- **Static Assets**: WhiteNoise
- **Testing**: Django Test Runner (17 unit & integration tests)

---

## 📖 Documentation & User Guide

For the complete step-by-step walkthrough, terminal commands, and feature guide, please refer to:

👉 **[USER_GUIDE.md](USER_GUIDE.md)**

---

## ⚡ Quick Start

```bash
# 1. Setup virtual environment & dependencies
source .venv/bin/activate
pip install -r requirements.txt

# 2. Run migrations
python manage.py migrate

# 3. Run test suite
python manage.py test core

# 4. Start local development server
python manage.py runserver
```
