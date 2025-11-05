# 🌐 Network Scanner

A lightweight Python-based network diagnostic tool that scans and identifies live hosts across a subnet or IP range.  
This project was built as part of my cybersecurity and automation toolkit to demonstrate skills in Python scripting, multithreading, and network analysis.

---

## 🔍 Features

- Scans a defined subnet or range of IPs  
- Detects live hosts using ICMP or ARP-based ping  
- Optionally scans common TCP ports  
- Multithreaded for improved performance  
- Command-line and modular Python design for easy integration  

---

## 🧩 Project Structure

NetworkScanner/
├── src/
│   ├── network_scanner.py        # Main scanning logic
│   └── utils/                    # (Optional) helper modules
│
├── examples/
│   └── scan_results.txt          # Example output (optional)
│
├── requirements.txt              # Dependencies / notes
├── README.md                     # Documentation
├── LICENSE                       # MIT license
└── .gitignore                    # Ignore compiled/build/system files

---

## ⚙️ Installation

git clone https://github.com/HughKnightOCE/NetworkScanner.git
cd NetworkScanner
pip install -r requirements.txt

---

## 🚀 Usage

Run the tool from your terminal or IDE:

python src/network_scanner.py

After execution, results will be saved in the `examples/scan_results.txt` file (or your chosen output path).

---

## 🧱 Requirements

The tool uses standard Python libraries.  
If additional dependencies are added later, include them in `requirements.txt`.

Example content:
os
time
subprocess
threading

---

## 📄 License

This project is licensed under the **MIT License** — see the `LICENSE` file for details.

---

## ✉️ Contact

Created by **Hugh Knight**  
📧 hugh.knight17@gmail.com  
🔗 GitHub: https://github.com/HughKnightOCE
