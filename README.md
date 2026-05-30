# 🕵️ OSINT Intel Bot — AI-Powered Intelligence Reports via Telegram

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)
![Telegram](https://img.shields.io/badge/Telegram-Bot-26A5E4?style=for-the-badge&logo=telegram)
![LLaMA](https://img.shields.io/badge/LLaMA_3.3_70B-Groq-F55036?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**Drop in a name, email, IP, domain, phone, or username — get a full intelligence report in seconds.**

[Features](#-features) • [Demo](#-demo) • [Installation](#-installation) • [Usage](#-usage) • [Architecture](#-architecture) • [Disclaimer](#-disclaimer)

</div>

---

## 🔍 What is this?

OSINT Intel Bot is an AI-powered Telegram bot that automates open-source intelligence gathering. You give it a target — it runs a full OSINT pipeline across dozens of sources and delivers a professional, branded PDF report right inside your Telegram chat.

No manual searching. No copy-pasting results. Just drop in a query and get a structured intelligence report in seconds.

---

## ✨ Features

| Feature | Description |
|--------|-------------|
| 🔎 **Google Dorking** | Automatically runs targeted dorks across LinkedIn, GitHub, social media, and data leak databases |
| 👤 **Username Search** | Searches 300+ platforms for active accounts using [Sherlock](https://github.com/sherlock-project/sherlock) |
| 🌐 **Domain & IP Recon** | Pulls DNS records, WHOIS data, and IP geolocation |
| 🤖 **AI Analysis** | Uses LLaMA 3.3 70B (via Groq API) to synthesize findings into a structured intelligence report |
| 📄 **PDF Export** | Delivers a clean, branded PDF report directly in Telegram |
| ⚡ **Parallel Execution** | All OSINT tasks run concurrently for maximum speed |

---

## 🎯 Supported Target Types

- 📧 Email addresses
- 👤 Names
- 🌐 IP addresses
- 🔗 Domains / URLs
- 📱 Phone numbers
- 🪪 Usernames / handles

---

## 📸 Demo

> _Screenshot or GIF of the bot in action — coming soon_

---

## 🛠 Tech Stack

- **[Python 3.10+](https://www.python.org/)** — Core language
- **[python-telegram-bot](https://github.com/python-telegram-bot/python-telegram-bot)** — Telegram bot framework
- **[Groq API](https://groq.com/)** — Ultra-fast LLaMA 3.3 70B inference
- **[Sherlock](https://github.com/sherlock-project/sherlock)** — Username OSINT across 300+ platforms
- **[FPDF](https://pyfpdf.readthedocs.io/)** — PDF generation
- **asyncio / ThreadPoolExecutor** — Parallel task execution

---

## 📦 Installation

### Prerequisites

- Python 3.10+
- A Telegram Bot Token (from [@BotFather](https://t.me/BotFather))
- A Groq API key (free at [groq.com](https://groq.com))

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/abdallahijjawe/OSINTBot.git
cd osint-intel-bot

# 2. Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install Sherlock
pip install sherlock-project

# 5. Configure environment variables
cp .env.example .env
```

Edit `.env` with your credentials:

```env
TELEGRAM_BOT_TOKEN=your_telegram_bot_token_here
GROQ_API_KEY=your_groq_api_key_here
```

### Run the bot

```bash
python bot.py
```

---

## 🚀 Usage

1. Start a chat with your bot on Telegram
2. Send `/start` to get a welcome message
3. Drop in any target:

```
/search john.doe@example.com
/search 192.168.1.1
/search johndoe
/search example.com
```

4. Wait a few seconds while the bot runs its pipeline
5. Receive your branded PDF intelligence report 📄

---

## 🏗 Architecture

```
User Input (Telegram)
        │
        ▼
  Target Classifier
        │
   ┌────┴────┐
   │         │
   ▼         ▼
Google     Sherlock
Dorking   (300+ sites)
   │         │
   ▼         ▼
DNS/WHOIS  IP Geolocation
   │         │
   └────┬────┘
        │
        ▼
  LLaMA 3.3 70B
  (Groq API — Analysis)
        │
        ▼
   FPDF Report Generator
        │
        ▼
  Telegram PDF Delivery
```

All OSINT modules run in **parallel** using `asyncio` and `ThreadPoolExecutor` for fast results.

---

## 📁 Project Structure

```
osint-intel-bot/
├── bot.py              # Main Telegram bot entrypoint
├── osint/
│   ├── dorker.py       # Google dork engine
│   ├── sherlock.py     # Username search wrapper
│   ├── dns_lookup.py   # DNS/WHOIS/IP recon
│   └── classifier.py   # Target type detection
├── ai/
│   └── analyzer.py     # Groq/LLaMA report generation
├── report/
│   └── pdf_builder.py  # FPDF branded report builder
├── .env.example
├── requirements.txt
└── README.md
```

---

## ⚙️ Configuration

| Variable | Description |
|----------|-------------|
| `TELEGRAM_BOT_TOKEN` | Your bot token from BotFather |
| `GROQ_API_KEY` | Groq API key for LLaMA inference |
| `MAX_RESULTS` | Max results per OSINT source (default: 10) |
| `REPORT_LOGO` | Path to your logo for PDF branding (optional) |

---

## 🤝 Contributing

Contributions are welcome! Feel free to:

- Open issues for bugs or feature requests
- Submit PRs for improvements
- Add new OSINT modules or data sources

```bash
# Fork, then clone your fork
git checkout -b feature/your-feature-name
git commit -m "Add: your feature description"
git push origin feature/your-feature-name
# Open a Pull Request
```

---

## ⚖️ Disclaimer

> **This tool is intended for educational purposes and authorized security research only.**
>
> - Only use this tool on targets you have **explicit permission** to investigate
> - The author is **not responsible** for any misuse or illegal activity
> - Always comply with your local laws and the terms of service of any platform queried
> - OSINT does not mean unlimited data access — **respect privacy**

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 📬 Contact

Built by **[Your Name]** — feel free to DM me on Telegram or open an issue.

> ⭐ If you found this useful, consider starring the repo!
