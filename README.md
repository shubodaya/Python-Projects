# 🐍 Python Automation Projects

Welcome to the **Python Automation Projects** repository a collection of real-world automation scripts and tools built using Python.

These projects are designed to automate a range of tasks including data processing, report generation, file management, server monitoring, and web interactions. They demonstrate practical applications of Python in IT operations, DevOps, and general productivity.

---

## 📁 Project Highlights

### 🔄 Catalog Update Automation
Automates the update of a product catalog with the following steps:
- Image conversion and resizing
- Uploading content (images and descriptions) to a web server
- PDF report generation
- Email delivery of reports
- System health checks and alerting

📂 See: [`catalog-update/`](./Automate-Update-to-Catalog/Readme.md)


### 📊 Automated Log Analyzer & Alerting
Monitors local or remote logs in real time to detect issues before they become critical:
- Collects logs from local folders or remote servers (SSH/Paramiko)
- Parses for failed logins, service crashes, suspicious activity
- Saves results into SQLite/CSV
- Sends alerts via Email/Slack when thresholds are crossed
- Runs continuously on a schedule

📂 See: [`log-analyzer/`](./Automated_log_analyzer/Readme.md)

> ⚙️ More projects coming soon...

---

## 🛠️ Built With

- Python 3
- Standard Library (`os`, `email`, `smtplib`, etc.)
- Third-party libraries:
  - `Pillow` – Image processing
  - `requests` – HTTP requests
  - `reportlab` – PDF generation
  - `psutil` – System monitoring

---

## 🚀 Getting Started

### Clone the repository:
```bash
git clone https://github.com/your-username/python-automation-projects.git
cd python-automation-projects
```

### (Optional) Set up a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

> Some projects may require external configuration such as file paths or server IP addresses. See individual project folders for instructions.

---

## 🤝 Contributing

Contributions are welcome! Feel free to fork the repository and submit a pull request with improvements, bug fixes, or new automation scripts.

---

## 📜 License

This repository is licensed under the [MIT License](LICENSE).

---

## 📬 Contact

Have suggestions or questions? Reach out at:  
📮 **hnshubodaya@gmail.com**
