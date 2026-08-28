import smtplib
import os
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)

SMTP_HOST = os.getenv("SMTP_HOST", "localhost")
SMTP_PORT = int(os.getenv("SMTP_PORT", 1025))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", "noreply@phishguard.ai")

def send_otp_email(to_email: str, otp: str) -> bool:
    """
    Send OTP email using standard SMTP.
    Works seamlessly with local mock servers like MailHog on localhost:1025
    or with real production SMTP relays.
    """
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Your Email Verification Code"
        msg["From"] = SMTP_FROM
        msg["To"] = to_email

        text = f"""Hello,

Your verification code is:
{otp}

This code will expire in 5 minutes.
If you did not request this code, please ignore this email.
"""
        msg.attach(MIMEText(text, "plain"))

        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10)
        
        # Only use TLS/Login if credentials are provided (i.e. not local MailHog)
        if SMTP_USER and SMTP_PASS:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            
        server.sendmail(SMTP_FROM, to_email, msg.as_string())
        server.quit()
        logger.info(f"OTP successfully delivered to {to_email} via SMTP ({SMTP_HOST}:{SMTP_PORT})")
            
        return True
    except Exception as e:
        logger.error(f"Error sending email to {to_email}: {e}")
        return False
