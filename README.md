
<div align="center">

# ⚡ WRAITH XSS ⚡
### Advanced Auto-Recon & Injection Engine

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-2.0.0-purple?style=for-the-badge)

<pre>
   ██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗    ██╗  ██╗███████╗███████╗
   ██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║    ╚██╗██╔╝██╔════╝██╔════╝
   ██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║     ╚███╔╝ ███████╗███████╗
   ██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║     ██╔██╗ ╚════██║╚════██║
   ╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║    ██╔╝ ██╗███████║███████║
    ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝    ╚═╝  ╚═╝╚══════╝╚══════╝
                                                      
                  [ NEURAL INTELLIGENCE CORE: ONLINE ]
</pre>

<p align="center">
  <b>Advanced Recon</b> • <b>Context-Aware Exploitation</b> • <b>Neural WAF Bypass</b> • <b>Cyberpunk Reporting</b>
</p>

</div>

---

## 📖 Overview

**WraithXSS** is an elite, all-in-one Cross-Site Scripting (XSS) scanner and reconnaissance framework. It integrates industry-standard tools with a custom "Neural Analysis" engine to detect, verify, and exploit XSS vulnerabilities with near-zero false positives.

Designed for modern bug bounty hunters, it features a hyper-stylized "Specter" dashboard, advanced WAF evasion, and automated reporting.

## ✨ Features

### 🧠 Neural Intelligence Engine
- **Context-Aware Analysis**: Detects if reflection is in HTML Body, Attribute, JS String, or Variable.
- **Polymorphic Payloads**: Automatically obfuscates payloads to bypass WAFs (Cloudflare, Akamai, AWS).
- **Zero False Positives**: Validates every reflection with a specialized canary check.

### 🌐 Integrated Recon Suite
- **Subdomain Discovery**: Powered by `subfinder`.
- **Live Host Probing**: Powered by `httpx`.
- **URL Harvesting**: Powered by `gau`.
- **Parameter Mining**: Powered by `paramspider` and `arjun`.

### 🛡️ WAF Detection & Evasion
- **Auto-Detection**: Identifies 10+ WAFs including Cloudflare, Imperva, and ModSecurity.
- **Smart Evasion**: Adapts payloads based on the detected WAF type.

### 📊 Elite Reporting
- **Cyberpunk HTML Reports**: High-tech, interactive HTML reports with vulnerability matrices.
- **Specter Profiles**: Save and restore your scanning sessions/state.
- **Real-time Webhooks**: distinct Discord & Slack alerts for critical findings.

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/Cyber-aditii/WraithXSS.git
cd WraithXSS

# Install Python requirements
pip3 install -r requirements.txt

# Run the interactive Specter Console
python3 WraithXSS.py
```

## 🛠️ Installation

### 1. Prerequisites
Ensure you have the following external tools installed and in your PATH (Go tools recommended):

```bash
# Install Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest

# ParamSpider & Arjun (Python tools)
pip3 install arjun
# Note: ParamSpider usually requires cloning its repo, ensure it is runnable as 'paramspider'
```

### 2. Python Dependencies
```bash
pip3 install -r requirements.txt
```

## 📖 Usage

### 🎮 Interactive Mode (Recommended)
Simply run the script without arguments to enter the **Neural Command Interface**:
```bash
python3 WraithXSS.py
```
**Specter Menu Options:**
1. **Full Automated Assault**: Runs the complete chain (Subdomains -> Hosts -> URLs -> Mining -> Analysis -> Exploitation).
2. **Modular Tools**: Run individual steps like Subfinder, HTTPX, or Arjun.
3. **Profile Management**: Save/Load your session "Neural Profile".
4. **Configuration**: Set up Discord/Slack webhooks.

### 💻 Command Line Mode
For quick, non-interactive scans (useful for piping or scripts):

```bash
# Basic scan targeting a domain
python3 WraithXSS.py -d example.com

# Custom output directory
python3 WraithXSS.py -d example.com -o /path/to/output

# Tuning performance
python3 WraithXSS.py -d example.com --threads 20 --timeout 15

# Disable deep scanning (quicker, less thorough)
python3 WraithXSS.py -d example.com --no-deep
```

## ⚙️ Configuration

| Argument | Description | Default |
|:---|:---|:---|
| `-d`, `--domain` | Target domain to scan | Required |
| `-o`, `--output` | Directory to save results | `output/domain_date` |
| `-t`, `--threads` | Number of threads for concurrent tasks | `10` |
| `--timeout` | HTTP Timeout in seconds | `30` |
| `--no-deep` | Skip deep crawling/historical discovery | `False` |
| `--no-fuzz` | Skip parameter fuzzing (Arjun) | `False` |

## 📂 Project Structure

```
WraithXSS/
├── WraithXSS.py        # Main engine & entry point
├── requirements.txt    # Python dependencies
├── output/             # Generated scan results
│   └── example.com_.../
│       ├── report.html     # Interactive Cyberpunk Report
│       ├── subdomains.txt  # Discovered Subdomains
│       ├── live_hosts.txt  # Live HTTP Services
│       ├── all_urls.txt    # Harvested Parameters
│       └── ...
└── README.md           # Documentation
```

## ⚠️ Disclaimer

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                           ⚠️  ETHICAL USE ONLY  ⚠️                            ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  This tool is intended for AUTHORIZED security testing only:                 ║
║                                                                              ║
║  ✅ Bug Bounty Programs (with explicit permission)                           ║
║  ✅ Authorized Penetration Testing                                           ║
║  ✅ Security Assessments (with signed authorization)                         ║
║                                                                              ║
║  ❌ Unauthorized access is ILLEGAL                                           ║
║  ❌ Using validated keys without permission is a CRIME                       ║
║                                                                              ║
║  The author is NOT responsible for any misuse of this tool.                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## 🤝 Contributing
Contributions are welcome! Feel free to open issues or submit pull requests.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 👨‍💻 Author

**Cyber-aditi**

[GitHub](https://github.com/Cyber-aditi)

<div align="center">
  <img src="https://img.shields.io/badge/Keep_Hacking-black?style=for-the-badge&logo=hackthebox" />
</div>
