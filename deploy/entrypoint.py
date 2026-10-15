#!/usr/bin/env python3
"""Supervise only this container's private PostgreSQL, sync and tunnel processes."""
import os
from pathlib import Path
import queue
import re
import secrets
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

children = {}
stopping = False
quick_cache = None

def stop_requested(_signal, _frame):
    global stopping
    stopping = True

def start(name, args, env, **kwargs):
    child = subprocess.Popen(args, env=env, **kwargs)
    children[name] = child
    return child

def check():
    if stopping:
        raise InterruptedError("Container shutdown requested")
    for name, child in children.items():
        if child.poll() is not None:
            raise RuntimeError(name + " exited; stopping the bundle")

def until_ready(callback, seconds, message):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        check()
        if callback():
            return
        time.sleep(.25)
    raise RuntimeError(message)

def private_file(path, value):
    temporary = path.with_name(path.name + ".new")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(value + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)

def database(env, data):
    if env.get("HAUNT_SYNC_DATABASE_URL"):
        return
    pgdata = data / "postgres"
    password_file = data / "database-password"
    selected = env.get("HAUNT_SYNC_DB_PASSWORD", "")
    if selected and not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", selected):
        raise ValueError("HAUNT_SYNC_DB_PASSWORD must have 32-256 URL-safe characters")
    if password_file.exists():
        password = password_file.read_text().strip()
        if selected and selected != password:
            raise ValueError("Database password differs from the saved installation")
    else:
        if (pgdata / "PG_VERSION").exists():
            raise ValueError("The saved database password file is missing")
        password = selected or secrets.token_hex(32)
        private_file(password_file, password)
    if not (pgdata / "PG_VERSION").exists():
        subprocess.run(["initdb", "-D", str(pgdata), "-U", "haunt_sync", "--pwfile=" + str(password_file), "--auth-host=scram-sha-256", "--auth-local=scram-sha-256", "--encoding=UTF8", "--locale=C"], check=True)
    start("database", ["postgres", "-D", str(pgdata), "-c", "listen_addresses=127.0.0.1", "-c", "port=5432", "-c", "unix_socket_directories=" + str(data / "run")], env)
    pg_env = dict(env, PGPASSWORD=password)
    def available():
        return subprocess.run(["pg_isready", "-h", "127.0.0.1", "-U", "haunt_sync"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    until_ready(available, 40, "Private database did not become ready")
    result = subprocess.run(["psql", "-h", "127.0.0.1", "-U", "haunt_sync", "-d", "postgres", "-Atc", "SELECT 1 FROM pg_database WHERE datname='haunt_sync'"], env=pg_env, capture_output=True, text=True, check=True)
    if result.stdout.strip() != "1":
        subprocess.run(["createdb", "-h", "127.0.0.1", "-U", "haunt_sync", "haunt_sync"], env=pg_env, check=True)
    env["HAUNT_SYNC_DATABASE_URL"] = "postgres://haunt_sync:" + password + "@127.0.0.1:5432/haunt_sync?sslmode=disable"

def main():
    global quick_cache
    if sys.argv[1:] == ["--version"]:
        os.execv("/usr/local/bin/haunt-sync", ["haunt-sync", "--version"])
    if len(sys.argv) > 1:
        raise ValueError("Unsupported container arguments; configure startup through environment values")
    os.umask(0o077)
    env = dict(os.environ)
    token = env.pop("HAUNT_SYNC_TUNNEL_TOKEN", "").strip()
    env.pop("TUNNEL_TOKEN", None)
    env.pop("TUNNEL_TOKEN_FILE", None)
    quick_setting = env.get("HAUNT_SYNC_QUICK_TUNNEL", "false")
    if quick_setting not in ("true", "false"):
        raise ValueError("HAUNT_SYNC_QUICK_TUNNEL must be true or false")
    quick = quick_setting == "true"
    if token and quick:
        raise ValueError("Choose a named tunnel token or Quick Tunnel mode, not both")
    if not token and not quick:
        raise ValueError("Set HAUNT_SYNC_TUNNEL_TOKEN or explicitly enable HAUNT_SYNC_QUICK_TUNNEL=true")
    if not quick:
        if not env.get("HAUNT_SYNC_ISSUER"):
            host = env.get("HAUNT_SYNC_HOST", "")
            if not host:
                raise ValueError("HAUNT_SYNC_HOST is required for a named tunnel")
            env["HAUNT_SYNC_ISSUER"] = "https://" + host
    elif env.get("HAUNT_SYNC_ISSUER"):
        raise ValueError("Quick Tunnel mode chooses its own temporary issuer; omit HAUNT_SYNC_ISSUER")
    if env.get("HAUNT_SYNC_TLS_CERT") or env.get("HAUNT_SYNC_TLS_KEY"):
        raise ValueError("The bundle uses Cloudflare HTTPS; use the standalone binary for direct TLS")
    env["HAUNT_SYNC_LISTEN_ADDR"] = "127.0.0.1:8090"
    env["HAUNT_SYNC_TRUSTED_PROXIES"] = "127.0.0.1/32,::1/128"
    data = Path("/data")
    (data / "run").mkdir(mode=0o700, parents=True, exist_ok=True)
    (data / "updates").mkdir(mode=0o755, exist_ok=True)
    if token:
        private_file(data / "run/cloudflared-token", token)
    else:
        # Never let a previously saved token silently override explicit Quick mode.
        (data / "run/cloudflared-token").unlink(missing_ok=True)
    env.setdefault("HAUNT_SYNC_UPDATES_DIR", str(data / "updates"))
    tunnel_args = ["cloudflared", "tunnel", "--no-autoupdate", "--metrics", "127.0.0.1:20241"]
    if quick:
        urls = queue.Queue()
        tunnel = start("tunnel", tunnel_args + ["--url", "http://127.0.0.1:8090"], env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        def logs():
            for line in tunnel.stdout:
                print(line, end="", flush=True)
                match = re.search(r"https://[a-z0-9-]+\.trycloudflare\.com", line)
                if match:
                    urls.put(match.group())
        threading.Thread(target=logs, daemon=True).start()
        until_ready(lambda: not urls.empty(), 90, "Cloudflare did not provide a temporary tunnel URL")
        env["HAUNT_SYNC_ISSUER"] = urls.get()
        print("Haunt Nexus temporary address: " + env["HAUNT_SYNC_ISSUER"], flush=True)
    database_directory = data
    if quick and not env.get("HAUNT_SYNC_DATABASE_URL"):
        # Random addresses are deliberately disposable sync instances. Keep
        # their snapshots separate from the named instance's data and keys.
        quick_cache = tempfile.TemporaryDirectory(prefix="nexus-quick-", dir=data)
        database_directory = Path(quick_cache.name)
        (database_directory / "run").mkdir(mode=0o700)
    private_file(data / "run/database-directory", str(database_directory))
    database(env, database_directory)
    start("sync", ["/usr/local/bin/haunt-sync"], env)
    def api_ready():
        try:
            with urllib.request.urlopen("http://127.0.0.1:8090/healthz", timeout=1) as response:
                return response.status == 200
        except Exception:
            return False
    until_ready(api_ready, 40, "Sync did not become ready; inspect its startup error")
    if not quick:
        start("tunnel", tunnel_args + ["run", "--token-file", str(data / "run/cloudflared-token")], env)
    print("Haunt Nexus ready: " + env["HAUNT_SYNC_ISSUER"], flush=True)
    while not stopping:
        check()
        time.sleep(.5)

def cleanup():
    # Finish sync requests before asking PostgreSQL to checkpoint and stop.
    for name in ("tunnel", "sync", "database"):
        child = children.get(name)
        if child is None or child.poll() is not None:
            continue
        child.send_signal(signal.SIGINT if name == "database" else signal.SIGTERM)
        try:
            child.wait(timeout=55 if name == "sync" else 15)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
    if quick_cache is not None:
        quick_cache.cleanup()

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, stop_requested)
    signal.signal(signal.SIGINT, stop_requested)
    code = 0
    try:
        main()
    except InterruptedError:
        pass
    except Exception as error:
        # Never include environment values, credentials or subprocess arguments.
        print("Haunt Nexus startup failed: " + (str(error) if isinstance(error, (ValueError, RuntimeError)) else type(error).__name__), file=sys.stderr, flush=True)
        code = 1
    finally:
        cleanup()
    sys.exit(code)
