# Network Scanner

A lightweight Python-based tool for scanning local or remote IP ranges and detecting active hosts.  
This project was built as part of my cybersecurity portfolio to demonstrate skills in networking, concurrency, and automation.

---

## 🔍 Features
- Scans a defined subnet or range of IPs.  
- Detects live hosts using ICMP or ARP-based ping.  
- Optional port scanning for common TCP ports.  
- Multithreaded for improved performance.  
- Command-line and modular Python design for easy integration.

---

## 🧩 Project Structure
NetworkScanner/
├── src/
│ ├── network_scanner.py # Main scanning logic 
│
├── examples/
│ └── scan_results.txt # Example output file (optional demo result)
│
├── requirements.txt # Dependencies and optional packages
├── README.md # Project documentation and setup guide
├── LICENSE # MIT license file
└── .gitignore # Ignore compiled, build, and system files

---

## ⚙️ Installation
```bash
git clone https://github.com/HughKnightOCE/NetworkScanner.git
cd NetworkScanner
pip install -r requirements.txt
```

---

## 🚀 Usage
```bash
python src/network_scanner.py
```

Optionally, adjust IP ranges and port lists inside the script before running.

---

## 🧠 About This Project
This tool was developed to practice networking fundamentals, automation, and Python scripting efficiency.  
It demonstrates the ability to interact with system commands, parse subprocess results, and utilise threading for concurrency.

---

## 📬 Contact
📧 **hugh.knight17@gmail.com**  
💼 [LinkedIn](https://www.linkedin.com/in/hugh-knight-australia)
