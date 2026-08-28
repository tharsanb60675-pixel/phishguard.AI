import smtplib
import subprocess
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def get_mx_server(email: str):
    domain = email.split('@')[1]
    output = subprocess.check_output(['nslookup', '-type=mx', domain]).decode()
    mx_records = []
    for line in output.split('\n'):
        if 'mail exchanger =' in line:
            parts = line.split('mail exchanger =')
            mx_server = parts[-1].strip()
            mx_records.append(mx_server)
    return mx_records[0] if mx_records else None

email = "random_test_email_1234567@gmail.com"
mx = get_mx_server(email)
print("MX:", mx)

msg = MIMEMultipart("alternative")
msg["Subject"] = "Test OTP"
msg["From"] = "noreply@phishguard.ai"
msg["To"] = email
msg.attach(MIMEText("Test 123", "plain"))

try:
    server = smtplib.SMTP(mx, 25, timeout=10)
    server.set_debuglevel(1)
    server.ehlo("phishguard.ai")
    server.starttls()
    server.ehlo("phishguard.ai")
    server.sendmail(msg["From"], email, msg.as_string())
    server.quit()
    print("SUCCESS")
except Exception as e:
    print("FAILED:", e)
