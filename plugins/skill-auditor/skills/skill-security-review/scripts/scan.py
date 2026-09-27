#!/usr/bin/env python3
"""Static, read-only scanner for Claude skills (and any folder of files).

It never executes, imports, or opens the network. It only reads files under
the given folder and prints a report. Standard library only, Python 3.8+.

Usage:
    python3 scan.py <folder> [--format md|json] [--max-bytes N]

The output is a triage aid for a human-style review, not a verdict. A clean
scan does not mean a skill is safe; every file must still be read.
"""

import argparse
import json
import os
import re
import stat
import sys

MAX_SNIPPET = 160
LONG_LINE = 500
DEFAULT_MAX_BYTES = 2_000_000

ARCHIVE_EXT = {
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar",
    ".whl", ".egg", ".dmg", ".pkg", ".deb", ".rpm", ".msi", ".mcpb", ".dxt",
}
BINARY_EXT = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".pyc", ".pyo",
    ".class", ".wasm", ".node",
}

MEDIA_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tif", ".tiff",
    ".mp3", ".wav", ".ogg", ".m4a", ".flac", ".mp4", ".mov", ".webm",
    ".ttf", ".otf", ".woff", ".woff2", ".pdf",
}

# (category, severity, regex). Severity: high / medium / info.
# Matches are leads for a reviewer, not proof of anything.
PATTERNS = [
    ("network", "medium", r"\b(curl|wget|Invoke-WebRequest|iwr|Invoke-RestMethod)\b"),
    ("network", "medium", r"https?://[^\s\"'<>)]+"),
    ("network", "medium", r"\b(requests|httpx|aiohttp|urllib|urllib3|http\.client)\b"),
    ("network", "medium", r"\b(fetch|axios|XMLHttpRequest|WebSocket)\s*\("),
    ("network", "high", r"\b(socket\.socket|net\.connect|nc\s+-|ncat|telnet)\b"),
    ("network", "high", r"(webhook|pastebin|ngrok|requestbin|discord(app)?\.com/api)"),
    ("exec", "high", r"\beval\s*\("),
    ("exec", "high", r"\bexec\s*\("),
    ("exec", "medium", r"\b(subprocess|os\.system|os\.popen|child_process|execSync|spawnSync|spawn\s*\()"),
    ("exec", "high", r"shell\s*=\s*True"),
    ("exec", "medium", r"\b(bash|sh|zsh|powershell|pwsh|cmd)\s+(-c|/c|-Command)\b"),
    ("exec", "high", r"(curl|wget)[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b"),
    ("secrets", "high", r"(\.ssh/|id_rsa|id_ed25519|\.aws/|\.gnupg|\.netrc|\.npmrc|\.pypirc|\.docker/config)"),
    ("secrets", "high", r"(keychain|security\s+find-generic-password|credential(s)?\.json|\.git-credentials)"),
    ("secrets", "medium", r"(\.env\b|api[_-]?key|secret[_-]?key|access[_-]?token|password|passwd|bearer\s)"),
    ("secrets", "medium", r"\b(ANTHROPIC|OPENAI|GITHUB|GH|AWS|GOOGLE)_[A-Z_]*(KEY|TOKEN|SECRET)\b"),
    ("filesystem", "medium", r"(\$HOME|~/|%USERPROFILE%|%APPDATA%|/etc/|/Users/|C:\\\\Users)"),
    ("destructive", "high", r"\brm\s+-(rf|fr|r)\b|\bRemove-Item\b.*-Recurse|shutil\.rmtree|\brmdir\s+/s"),
    ("destructive", "high", r"\b(sudo|doas|mkfs|dd\s+if=|chmod\s+(-R\s+)?777|chown\s+-R)\b"),
    ("persistence", "high", r"(crontab|launchctl|LaunchAgents|systemctl|schtasks|\.bashrc|\.zshrc|\.bash_profile|\.profile\b|RunOnce)"),
    ("persistence", "high", r"(\.claude/settings(\.local)?\.json|CLAUDE\.md|\.claude/skills|\.claude/agents|\.mcp\.json|hooks\.json)"),
    ("install", "medium", r"\b(pip3?\s+install|npm\s+(i|install)\b|npx\s|pnpm\s+(add|dlx)|yarn\s+(add|dlx)|brew\s+install|apt(-get)?\s+install|gem\s+install|cargo\s+install|go\s+install|uvx?\s)"),
    ("obfuscation", "high", r"\b(base64|b64decode|atob|fromCharCode|codecs\.decode|marshal\.loads|zlib\.decompress)\b"),
    ("obfuscation", "medium", r"(\\x[0-9a-fA-F]{2}){6,}"),
    ("obfuscation", "medium", r"[A-Za-z0-9+/]{120,}={0,2}"),
    ("injection", "high", r"(?i)ignore\s+(all\s+|any\s+)?(previous|prior|above)\s+(instructions|rules)"),
    ("injection", "high", r"(?i)(do\s+not|don'?t|never)\s+(tell|inform|mention|reveal|show)\s+(this\s+to\s+)?(the\s+)?user"),
    ("injection", "high", r"(?i)(you\s+are\s+now|new\s+system\s+prompt|override\s+(your|the)\s+(instructions|system)|jailbreak)"),
    ("injection", "medium", r"(?i)(without\s+asking|without\s+(the\s+)?user'?s?\s+(permission|consent|approval)|silently|secretly)"),
    ("injection", "medium", r"(?i)(dangerously-skip-permissions|bypassPermissions|--no-verify|disable\s+safety)"),
]
COMPILED = [(c, s, re.compile(p)) for c, s, p in PATTERNS]

HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)

# Zero-width, bidi controls, and Unicode tag characters (used to hide text).
HIDDEN_CHARS = re.compile(
    "[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]"
)

SEV_ORDER = {"high": 0, "medium": 1, "info": 2}

RISKY_FRONTMATTER = {
    "allowed-tools": "pre-approves tools without asking",
    "hooks": "registers hooks that keep running for the rest of the session",
    "context": "can run in a forked subagent",
    "agent": "chooses a subagent type",
    "model": "switches the model",
    "shell": "chooses the shell for inline commands",
    "disallowed-tools": "removes tools while active",
}


def is_binary(path, sample=8192):
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(sample)
    except OSError:
        return True
    return b"\x00" in chunk


def rel(root, path):
    return os.path.relpath(path, root).replace(os.sep, "/")


def snippet(text):
    text = text.strip().replace("\t", " ")
    return text if len(text) <= MAX_SNIPPET else text[: MAX_SNIPPET - 3] + "..."


def parse_frontmatter(text):
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end == -1:
        return None
    block = text[3:end]
    keys = {}
    for line in block.splitlines():
        m = re.match(r"^([A-Za-z0-9_-]+)\s*:\s*(.*)$", line)
        if m:
            keys[m.group(1)] = m.group(2).strip()
    return keys


def scan(root, max_bytes=DEFAULT_MAX_BYTES):
    root = os.path.abspath(root)
    real_root = os.path.realpath(root)
    report = {
        "root": root,
        "files": [],
        "flags": [],
        "matches": [],
        "frontmatter": [],
        "skipped": [],
    }

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d != ".git")
        for d in list(dirnames):
            full = os.path.join(dirpath, d)
            if os.path.islink(full):
                target = os.path.realpath(full)
                outside = not target.startswith(real_root + os.sep)
                report["flags"].append({
                    "file": rel(root, full), "kind": "symlink-dir",
                    "detail": "directory symlink -> " + target + (" (OUTSIDE the skill folder)" if outside else ""),
                    "severity": "high" if outside else "medium",
                })
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            r = rel(root, full)
            try:
                st = os.lstat(full)
            except OSError as exc:
                report["skipped"].append({"file": r, "reason": str(exc)})
                continue

            entry = {"file": r, "size": st.st_size, "type": "text"}
            report["files"].append(entry)

            if stat.S_ISLNK(st.st_mode):
                target = os.path.realpath(full)
                outside = not target.startswith(real_root + os.sep)
                entry["type"] = "symlink"
                report["flags"].append({
                    "file": r, "kind": "symlink",
                    "detail": "symlink -> " + target + (" (OUTSIDE the skill folder)" if outside else ""),
                    "severity": "high" if outside else "medium",
                })
                continue

            if any(part.startswith(".") for part in r.split("/")):
                report["flags"].append({"file": r, "kind": "hidden", "detail": "hidden file or folder", "severity": "info"})
            if st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                report["flags"].append({"file": r, "kind": "executable", "detail": "has the executable bit", "severity": "info"})

            ext = os.path.splitext(name)[1].lower()
            if ext in ARCHIVE_EXT:
                entry["type"] = "archive"
                report["flags"].append({"file": r, "kind": "archive", "detail": "archive: contents cannot be reviewed in place", "severity": "high"})
                continue
            if ext in MEDIA_EXT and ext not in BINARY_EXT:
                entry["type"] = "media"
                report["flags"].append({"file": r, "kind": "media", "detail": "media/font/PDF file: not reviewed as text (usually inert; check it is what the name says)", "severity": "info"})
                continue
            if ext in BINARY_EXT or is_binary(full):
                entry["type"] = "binary"
                report["flags"].append({"file": r, "kind": "binary", "detail": "binary file: cannot be reviewed as text", "severity": "high"})
                continue
            if st.st_size > max_bytes:
                entry["type"] = "too-large"
                report["skipped"].append({"file": r, "reason": "larger than %d bytes; read it manually" % max_bytes})
                continue

            try:
                with open(full, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError as exc:
                report["skipped"].append({"file": r, "reason": str(exc)})
                continue

            lines = text.splitlines()
            longest = max((len(l) for l in lines), default=0)
            if longest > LONG_LINE:
                report["flags"].append({
                    "file": r, "kind": "long-line",
                    "detail": "longest line is %d chars (possible minified or obfuscated content)" % longest,
                    "severity": "medium",
                })

            for i, line in enumerate(lines, 1):
                hidden = HIDDEN_CHARS.findall(line)
                if hidden:
                    codes = sorted({"U+%04X" % ord(c) for c in hidden})
                    report["matches"].append({
                        "category": "hidden-unicode", "severity": "high", "file": r, "line": i,
                        "text": "invisible characters " + ", ".join(codes[:6]),
                    })
                best = {}  # one row per category per line, keeping the highest severity
                for cat, sev, rx in COMPILED:
                    if rx.search(line) and (cat not in best or SEV_ORDER[sev] < SEV_ORDER[best[cat]]):
                        best[cat] = sev
                for cat, sev in best.items():
                    report["matches"].append({
                        "category": cat, "severity": sev, "file": r, "line": i,
                        "text": snippet(line),
                    })

            if ext in {".md", ".markdown", ".html", ".htm", ".txt"}:
                for m in HTML_COMMENT.finditer(text):
                    body = m.group(1).strip()
                    if body:
                        line_no = text.count("\n", 0, m.start()) + 1
                        report["matches"].append({
                            "category": "hidden-comment", "severity": "medium", "file": r, "line": line_no,
                            "text": "HTML comment (invisible when rendered): " + snippet(body),
                        })

            if name == "SKILL.md":
                fm = parse_frontmatter(text)
                info = {"file": r, "keys": fm or {}, "notes": []}
                if fm is None:
                    info["notes"].append("no frontmatter found")
                else:
                    for key, why in RISKY_FRONTMATTER.items():
                        if key in fm:
                            info["notes"].append("`%s` is set: %s" % (key, why))
                    if fm.get("disable-model-invocation", "").lower() != "true":
                        info["notes"].append("can auto-activate (disable-model-invocation is not true)")
                    if "paths" not in fm and fm.get("disable-model-invocation", "").lower() != "true":
                        info["notes"].append("no `paths` limit: may activate in any project")
                report["frontmatter"].append(info)

    return report



def to_markdown(rep):
    out = []
    out.append("# Static scan: `%s`\n" % rep["root"])
    out.append("> Triage aid only. A clean scan does not mean the skill is safe. Read every file.\n")

    out.append("## Files (%d)\n" % len(rep["files"]))
    out.append("| File | Size | Type |")
    out.append("| --- | ---: | --- |")
    for f in rep["files"]:
        out.append("| `%s` | %d | %s |" % (f["file"], f["size"], f["type"]))
    out.append("")

    out.append("## SKILL.md frontmatter\n")
    if not rep["frontmatter"]:
        out.append("No `SKILL.md` found.\n")
    for fm in rep["frontmatter"]:
        out.append("**`%s`**\n" % fm["file"])
        for k, v in fm["keys"].items():
            out.append("- `%s`: %s" % (k, v if v else "(multi-line or empty)"))
        for n in fm["notes"]:
            out.append("- NOTE: " + n)
        out.append("")

    out.append("## File-level flags (%d)\n" % len(rep["flags"]))
    for f in sorted(rep["flags"], key=lambda x: (SEV_ORDER[x["severity"]], x["file"])):
        out.append("- [%s] `%s` - %s" % (f["severity"], f["file"], f["detail"]))
    out.append("")

    out.append("## Pattern matches (%d)\n" % len(rep["matches"]))
    if rep["matches"]:
        counts = {}
        for m in rep["matches"]:
            counts[m["category"]] = counts.get(m["category"], 0) + 1
        out.append("By category: " + ", ".join("%s %d" % kv for kv in sorted(counts.items())) + "\n")
        out.append("| Sev | Category | Location | Text |")
        out.append("| --- | --- | --- | --- |")
        for m in sorted(rep["matches"], key=lambda x: (SEV_ORDER[x["severity"]], x["category"], x["file"], x["line"])):
            text = m["text"].replace("|", "\\|")
            out.append("| %s | %s | `%s:%d` | `%s` |" % (m["severity"], m["category"], m["file"], m["line"], text.replace("`", "'")))
    out.append("")

    out.append("## Not scanned (%d)\n" % len(rep["skipped"]))
    for s in rep["skipped"]:
        out.append("- `%s` - %s" % (s["file"], s["reason"]))
    return "\n".join(out) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Read-only static scan of a skill folder.")
    ap.add_argument("folder")
    ap.add_argument("--format", choices=["md", "json"], default="md")
    ap.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    args = ap.parse_args(argv)

    if not os.path.isdir(args.folder):
        print("error: not a folder: %s" % args.folder, file=sys.stderr)
        return 2
    rep = scan(args.folder, args.max_bytes)
    if args.format == "json":
        json.dump(rep, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(to_markdown(rep))
    return 0


if __name__ == "__main__":
    sys.exit(main())
