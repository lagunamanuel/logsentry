# 🛡️ LogSentry

LogSentry is a Python-based security command-line tool designed to parse log files, extract suspicious IP addresses based on occurrence thresholds, and analyze them using the VirusTotal v3 API. 

## ✨ Features

* **Strict Parsing:** Utilizes robust regular expressions to extract only valid IPv4 addresses.
* **Threshold Control:** Filters out noise by only analyzing IPs that exceed a user-defined threshold of occurrences.
* **VirusTotal Integration:** Automatically checks suspicious IPs against multiple security engines to determine if they are malicious.
* **Rate Limit Aware:** Smartly handles VirusTotal's public API limits (4 requests/min) with built-in delays, preventing account bans.
* **Local Mode:** Includes a `--no-vt` flag for fast, local-only parsing without making any API calls.

## ⚙️ Prerequisites

* Python 3.8 or higher.
* A [VirusTotal API Key](https://www.virustotal.com/) (the free tier is fully supported).

## 🚀 Installation

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/lagunamanuel/logsentry.git](https://github.com/lagunamanuel/logsentry.git)
   cd logsentry
   ```

2. **Create and activate a virtual environment (recommended):**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up your environment variables:**
   You must export your VirusTotal API key before running the tool:
   ```bash
   export VT_API_KEY="your_api_key_here"
   ```
   *(Tip: You can add this line to your `~/.bashrc` or `~/.zshrc` to make it persistent).*