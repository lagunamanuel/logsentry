# 🛡️ LogSentry

LogSentry is a Python-based security command-line tool designed to parse log files, extract suspicious IP addresses based on occurrence thresholds, and analyze them using the VirusTotal v3 API. 

## ✨ Features

* **Strict Parsing:** Utilizes robust regular expressions to extract only valid IPv4 addresses.
* **Threshold Control:** Filters out noise by only analyzing IPs that exceed a user-defined threshold of occurrences.
* **VirusTotal Integration:** Automatically checks suspicious IPs against multiple security engines to determine if they are malicious.
* **Rate Limit Aware:** Smartly handles VirusTotal's public API limits (4 requests/min) with built-in delays, preventing account bans.
* **Local Mode:** Includes a `--no-vt` flag for fast, local-only parsing without making any API calls.
