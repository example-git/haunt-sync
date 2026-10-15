#!/usr/bin/env python3
"""Check tracked files and private/output boundaries without reading secrets."""

from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def git(*args: str, input: bytes | None = None) -> bytes:
    result = subprocess.run(
        ["git", *args], cwd=ROOT, input=input, capture_output=True, check=False
    )
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr.decode("utf-8", "replace"))
    return result.stdout


def ignored(paths: list[str]) -> set[str]:
    if not paths:
        return set()
    data = git(
        "check-ignore",
        "--no-index",
        "-z",
        "--stdin",
        input=b"\0".join(path.encode() for path in paths) + b"\0",
    )
    return {path.decode() for path in data.split(b"\0") if path}


def main() -> int:
    files = [path.decode() for path in git("ls-files", "-z").split(b"\0") if path]
    problems = [f"Tracked private/output file: {path}" for path in sorted(ignored(files))]

    private = [
        ".env",
        ".env.local",
        ".env.production",
        ".envrc",
        ".netrc",
        ".pgpass",
        "credentials.json",
        "secrets/tunnel-token",
        ".local/sync-updates/haunt-updates.json",
        ".local/sync-mail/tls/server.key",
        ".local/sync-mail/dkim/haunt.private",
        "data/postgres/PG_VERSION",
        "backups/sync.dump",
        "state.sqlite3",
        "database.dump",
        "haunt-sync",
        "release/haunt-sync-linux-amd64",
        "bin/haunt-sync",
        "build/output.bin",
        "dist/archive.tar.gz",
        "out/report.txt",
        "tmp/trace.json",
        "coverage/lcov.info",
        "coverage.out",
        "cpu.pprof",
        "debug.log",
        "test-results/trace.zip",
        "scripts/__pycache__/check.pyc",
        "AGENTS.md",
        "AGENTS.local.md",
        ".codex/config.toml",
        ".claude/settings.json",
        ".idea/workspace.xml",
        ".vscode/settings.json",
        ".DS_Store",
        "file.swp",
        "file~",
    ]
    required = [
        ".dockerignore",
        ".env.example",
        ".gitattributes",
        ".github/workflows/verify.yml",
        ".gitignore",
        "CONTRIBUTING.md",
        "Dockerfile",
        "LICENSE",
        "README.md",
        "SECURITY.md",
        "cmd/haunt-sync/main.go",
        "compose.mail.yml",
        "compose.yml",
        "deploy/entrypoint.py",
        "docs/architecture.md",
        "docs/deployment.md",
        "docs/development.md",
        "docs/index.md",
        "docs/mail.md",
        "docs/operations.md",
        "docs/security.md",
        "docs/updates.md",
        "go.mod",
        "go.sum",
        "internal/service/schema.sql",
        "mail-relay/entrypoint.py",
        "scripts/check-docs.py",
        "scripts/check-repository.py",
    ]

    problems += [
        f"Missing ignore rule: {path}"
        for path in sorted(set(private) - ignored(private))
    ]
    problems += [
        f"Required source is ignored: {path}" for path in sorted(ignored(required))
    ]
    problems += [
        f"Required source is missing: {path}"
        for path in required
        if not (ROOT / path).exists()
    ]

    for path in files:
        source = ROOT / path
        if source.is_file() and source.stat().st_size > 2 << 20:
            problems.append(f"Unexpected tracked file larger than 2 MiB: {path}")

    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    print(
        f"Repository hygiene passed: {len(files)} tracked paths; "
        f"{len(private)} private/output and {len(required)} source boundaries checked."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
