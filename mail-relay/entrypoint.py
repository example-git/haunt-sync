"""Private send-only relay. No host ports, inboxes, or plaintext submission."""
import ipaddress
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time

host = os.environ["HAUNT_MAIL_HOST"]
domain = os.environ["HAUNT_MAIL_DOMAIN"]
sender = os.environ["HAUNT_MAIL_FROM"]
network = str(ipaddress.ip_network(os.environ["HAUNT_MAIL_TRUSTED_NETWORK"], strict=True))
for value in (host, domain):
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value):
        raise ValueError("Invalid mail domain")
if not re.fullmatch(r"[a-zA-Z0-9._+-]+@" + re.escape(domain), sender):
    raise ValueError("Sender must belong to the configured mail domain")
run = Path("/run/haunt-mail")
run.mkdir(mode=0o700, exist_ok=True)
key = run / "haunt.private"
shutil.copyfile("/dkim/haunt.private", key)
shutil.chown(key, user="opendkim", group="opendkim")
key.chmod(0o600)
run.chmod(0o755)
(run / "trusted-hosts").write_text("127.0.0.1\n::1\n" + network + "\n")
(run / "opendkim.conf").write_text(f"""Syslog no
LogWhy no
Mode s
Canonicalization relaxed/relaxed
Socket inet:8891@127.0.0.1
UserID opendkim
Domain {domain}
Selector haunt
KeyFile {key}
InternalHosts {run}/trusted-hosts
OversignHeaders From
""")
config = {
    "compatibility_level": "3.6",
    "myhostname": host,
    "mydomain": domain,
    "myorigin": domain,
    "mydestination": "",
    "relay_domains": "",
    "inet_interfaces": "all",
    "inet_protocols": "ipv4",
    "mynetworks": "127.0.0.0/8 " + network,
    "smtpd_client_restrictions": "permit_mynetworks, reject",
    "smtpd_relay_restrictions": "permit_mynetworks, reject",
    "smtpd_sender_restrictions": "check_sender_access regexp:/run/haunt-mail/senders, reject",
    "smtpd_tls_security_level": "encrypt",
    "smtpd_tls_cert_file": "/tls/server.crt",
    "smtpd_tls_key_file": "/tls/server.key",
    "smtpd_tls_protocols": ">=TLSv1.2",
    "smtpd_tls_mandatory_protocols": ">=TLSv1.2",
    "smtp_tls_security_level": "encrypt",
    "smtp_tls_CAfile": "/etc/ssl/certs/ca-certificates.crt",
    "smtpd_milters": "inet:127.0.0.1:8891",
    "non_smtpd_milters": "inet:127.0.0.1:8891",
    "milter_default_action": "tempfail",
    "milter_protocol": "6",
    "maillog_file": "/dev/stdout",
    "alias_maps": "",
    "alias_database": "",
    "message_size_limit": "65536",
    "default_process_limit": "20",
    "smtpd_client_message_rate_limit": "30",
    "anvil_rate_time_unit": "60s",
    "maximal_queue_lifetime": "10m",
    "bounce_queue_lifetime": "10m",
    "minimal_backoff_time": "60s",
    "maximal_backoff_time": "300s",
}
(run / "senders").write_text("/^" + re.escape(sender) + "$/ OK\n")
Path("/etc/postfix/main.cf").write_text("".join(k + " = " + v + "\n" for k, v in config.items()))
Path("/etc/postfix/master.cf").write_text("""submission inet n - n - - smtpd
pickup unix n - n 60 1 pickup
cleanup unix n - n - 0 cleanup
qmgr unix n - n 300 1 qmgr
tlsmgr unix - - n 1000? 1 tlsmgr
rewrite unix - - n - - trivial-rewrite
bounce unix - - n - 0 bounce
defer unix - - n - 0 bounce
trace unix - - n - 0 bounce
verify unix - - n - 1 verify
flush unix n - n 1000? 0 flush
proxymap unix - - n - - proxymap
proxywrite unix - - n - 1 proxymap
smtp unix - - n - - smtp
relay unix - - n - - smtp
showq unix n - n - - showq
error unix - - n - - error
retry unix - - n - - error
discard unix - - n - - discard
local unix - n n - - local
virtual unix - n n - - virtual
lmtp unix - - n - - lmtp
anvil unix - - n - 1 anvil
scache unix - - n - 1 scache
postlog unix-dgram n - n - 1 postlogd
""")
subprocess.run(["postfix", "set-permissions"], check=True)
subprocess.run(["postfix", "check"], check=True)
children = []
stopping = False
def stop(*_):
    global stopping
    stopping = True
signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
try:
    children.append(subprocess.Popen(["opendkim", "-f", "-x", str(run / "opendkim.conf")]))
    children.append(subprocess.Popen(["postfix", "start-fg"]))
    while not stopping:
        for child in children:
            if child.poll() is not None:
                raise RuntimeError("Mail relay child exited")
        time.sleep(.5)
finally:
    subprocess.run(["postfix", "stop"], check=False, timeout=15)
    for child in children:
        if child.poll() is None:
            child.terminate()
    for child in children:
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
