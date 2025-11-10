# 🧠 Network Port Scanner with AI-Powered Vulnerability Analysis

This tool performs a **network port scan** using Nmap and then analyzes the scan results with a **local Mistral LLM** (via Ollama) to identify potential vulnerabilities, misconfigurations, and security risks.

It’s a lightweight, privacy-preserving way to combine **real network data** with **AI-driven vulnerability intelligence**, all running locally on your machine.

---

## ⚙️ Features

- 🔍 **Port Scanning** – Uses Nmap with service and version detection (`-sV`)
- 🌐 **Flexible Scan Modes**
  - Automatic (1–1024)
  - Manual (custom port range)
  - Complete (1–65535)
- 🤖 **AI Vulnerability Analysis** – Uses Mistral LLM to analyze open services
- 💡 **Readable Reports** – Human-readable vulnerability bulletins
- 🧩 **JSON Output** – Includes scan data + AI analysis results

---

## 🧰 Requirements

### 1. System Dependencies

You **must** have these installed locally:

| Dependency | Purpose | Installation |
|-------------|----------|---------------|
| **Nmap** | Performs the actual network scan | Ubuntu/Debian → `sudo apt install nmap`<br>macOS → `brew install nmap`<br>Windows → [https://nmap.org/download.html](https://nmap.org/download.html) |
| **Ollama** | Runs the Mistral LLM locally | Download from [https://ollama.com/download](https://ollama.com/download) |
| **Mistral Model** | LLM used for analysis | Run: `ollama pull mistral` |

> ⚠️ Nmap requires elevated privileges for certain scans (`sudo` on Linux/macOS or “Run as Administrator” on Windows).

---

### 2. Python Dependencies

Create a virtual environment and install:

```bash
python3 -m venv venv
source venv/bin/activate   # (Windows: venv\Scripts\activate)
pip install -r requirements.txt
