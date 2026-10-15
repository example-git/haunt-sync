import smtplib
import ssl
context = ssl.create_default_context(cafile="/tls/ca.crt")
with smtplib.SMTP("localhost", 587, timeout=5) as client:
    client.ehlo()
    client.starttls(context=context)
    client.ehlo()
    if client.noop()[0] != 250:
        raise RuntimeError("SMTP relay is not ready")
