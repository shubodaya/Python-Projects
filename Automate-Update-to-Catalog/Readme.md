# **Automate Updates to Catalog Information**

This project was completed as part of the **Google IT Automation with Python Professional Certificate**. It automates the process of updating an online fruit store's product catalog, including:

- 🖼️ Image processing  
- 📤 Data and image upload  
- 📑 PDF report generation  
- 🛡️ System monitoring and alerting  

---

## **📸 1. Image Processing**

### **Script:** `changeImage.py`

Processes images in the `~/supplier-data/images` directory:

- 🔄 Converts `.tiff` files to `.jpeg`
- 📏 Resizes images to `600x400` pixels
- 🎨 Converts color space from RGBA to RGB

```python
#!/usr/bin/env python3
from PIL import Image
import os

path = "./supplier-data/images/"
for f in os.listdir(path):
    if f.endswith(".tiff"):
        im = Image.open(path + f).convert("RGB")
        im.resize((600, 400)).save(path + f.replace(".tiff", ".jpeg"), "JPEG")
```

---

## **📤 2. Data Upload**

### **Upload Images – `supplier_image_upload.py`**

Uploads JPEG images to the `/upload/` endpoint of the server.

```python
#!/usr/bin/env python3
import requests
import os

url = "http://localhost/upload/"  # Replace with actual external IP
for f in os.listdir("./supplier-data/images"):
    if f.endswith(".jpeg"):
        with open('./supplier-data/images/' + f, 'rb') as opened:
            r = requests.post(url, files={'file': opened})
```

---

### **Upload Descriptions – `run.py`**

Parses text files and uploads fruit info to `/fruits/` as JSON.

📁 Text files include: `name`, `weight (e.g. 500 lbs)`, `description`  
🔄 Weight is converted to an integer  
🖼️ Associates image by filename (e.g., `001.txt` → `001.jpeg`)

```python
#!/usr/bin/env python3
import os
import requests

fruits = {}
keys = ["name", "weight", "description", "image_name"]
index = 0
path = "./supplier-data/descriptions/"

for file in os.listdir(path):
    with open(path + file) as f:
        for ln in f:
            line = ln.strip()
            if "lbs" in line:
                fruits["weight"] = int(line.split()[0])
                index += 1
            else:
                fruits[keys[index]] = line
                index += 1
        fruits["image_name"] = file.replace(".txt", ".jpeg")
        response = requests.post("http://<External_IP>/fruits/", json=fruits)
        fruits.clear()
```

---

## **📑 3. Reporting**

### **Generate PDF Report – `reports.py`**

Generates `processed.pdf` containing fruit info:

```python
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

def generate_report(attachment, title, paragraph):
    styles = getSampleStyleSheet()
    report = SimpleDocTemplate(attachment)
    report_title = Paragraph(title, styles["h1"])
    report_info = Paragraph(paragraph, styles["BodyText"])
    empty_line = Spacer(1, 20)
    report.build([report_title, empty_line, report_info])
```

---

### **Send Email – `report_email.py`**

Sends email with the PDF report attached.

```python
import datetime, os, reports, emails

date = "Processed Update on " + datetime.date.today().strftime("%B %d, %Y")
summary = "name: Apple<br />weight: 500 lbs<br /><br />..."

reports.generate_report("/tmp/processed.pdf", date, summary)

sender = "automation@example.com"
receiver = "{}@example.com".format(os.environ.get('USER'))
subject = "Upload Completed - Online Fruit Store"
body = "All fruits are uploaded to our website successfully. A detailed list is attached."

message = emails.generate_email(sender, receiver, subject, body, "/tmp/processed.pdf")
emails.send_email(message)
```

---

## **📬 4. Email Utility – `emails.py`**

Custom module to generate and send email with or without attachments.

```python
import email.message, mimetypes, os.path, smtplib

def generate_email(sender, recipient, subject, body, attachment_path):
    message = email.message.EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)

    if attachment_path:
        attachment_filename = os.path.basename(attachment_path)
        mime_type, _ = mimetypes.guess_type(attachment_path)
        mime_type, mime_subtype = mime_type.split('/', 1)

        with open(attachment_path, 'rb') as ap:
            message.add_attachment(ap.read(), maintype=mime_type, subtype=mime_subtype, filename=attachment_filename)
    return message

def generate_error_email(sender, recipient, subject, body):
    message = email.message.EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)
    return message

def send_email(message):
    mail_server = smtplib.SMTP('localhost')
    mail_server.send_message(message)
    mail_server.quit()
```

---

## **🛡️ 5. System Monitoring – `health_check.py`**

Monitors system health every 60 seconds. Sends alerts if:

- ⚠️ **CPU usage > 80%**  
- 💾 **Disk space < 20% available**  
- 🧠 **Memory < 100MB available**  
- 🌐 **Hostname "localhost" not resolving to 127.0.0.1**

```python
import shutil, psutil, socket, emails, os

sender = "automation@example.com"
receiver = "{}@example.com".format(os.environ.get('USER'))
body = "Please check your system and resolve the issue as soon as possible."

if shutil.disk_usage("/").free / shutil.disk_usage("/").total * 100 < 20:
    subject = "Error - Available disk space is less than 20%"
    emails.send_email(emails.generate_error_email(sender, receiver, subject, body))

if psutil.cpu_percent(1) > 80:
    subject = "Error - CPU usage is over 80%"
    emails.send_email(emails.generate_error_email(sender, receiver, subject, body))

if psutil.virtual_memory().available < 100 * 1024 * 1024:
    subject = "Error - Available memory is less than 100MB"
    emails.send_email(emails.generate_error_email(sender, receiver, subject, body))

try:
    if socket.gethostbyname("localhost") != "127.0.0.1":
        raise Exception
except:
    subject = "Error - localhost cannot be resolved to 127.0.0.1"
    emails.send_email(emails.generate_error_email(sender, receiver, subject, body))
```

---

## ✅ **Conclusion**

This project integrates Python automation across image manipulation, data serialization, REST APIs, PDF generation, emailing, and system monitoring. It’s an end-to-end solution showcasing practical DevOps and backend automation skills.
