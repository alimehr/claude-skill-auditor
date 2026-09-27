# Claude Skill Auditor

**Check a third-party Claude skill before you install it.**

Skills are powerful: a `SKILL.md` can tell Claude to run commands, and a skill folder can ship scripts that run on your machine. Most community skills are fine. A careless or malicious one can read your credentials, send data somewhere, change your settings, or hide instructions for Claude in places you won't see.

`skill-security-review` gives Claude a fixed, careful procedure for reviewing a skill **before** it can do anything:

1. **Quarantine**: clone or copy the skill into a folder Claude never loads skills from.
2. **Scan**: run a small, read-only scanner that flags risky files and patterns.
3. **Read everything**: Claude reads every file line by line and checks each scan hit in context.
4. **Report and stop**: you get a plain-language report with `file:line` findings, a risk level and a recommendation. Nothing is installed.
5. **Install on approval**: only after you say yes, into **one project** you name, as **manual-only** (it will not activate by itself).

> [!IMPORTANT]
> This is a review aid, not a guarantee. An AI review can miss things, and a clean scan proves nothing. For anything sensitive, read the code yourself too. See [Limitations](#limitations).

---

## Contents

- [Quick start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [What gets checked](#what-gets-checked)
- [The report](#the-report)
- [How installing works](#how-installing-works)
- [The scanner on its own](#the-scanner-on-its-own)
- [Limitations](#limitations)
- [FAQ](#faq)
- [Repository layout](#repository-layout)
- [Contributing](#contributing) · [Security](#security) · [License](#license)

---

## Quick start

In Claude Code:

```text
/plugin marketplace add alimehr/claude-skill-auditor
/plugin install skill-auditor@claude-skill-auditor
```

Then, in any chat:

```text
/skill-auditor:skill-security-review https://github.com/some-user/some-skill
```

Or just ask: *"Review this skill before I install it: https://github.com/some-user/some-skill"*.

---

## Installation

Pick one. You should review this skill before installing it, too; it is two files (`SKILL.md` and `scripts/scan.py`), both short and readable.

### Option 1: Claude Code plugin (recommended)

```text
/plugin marketplace add alimehr/claude-skill-auditor
/plugin install skill-auditor@claude-skill-auditor
```

Or from your shell:

```bash
claude plugin marketplace add alimehr/claude-skill-auditor
claude plugin install skill-auditor@claude-skill-auditor
```

Run it as `/skill-auditor:skill-security-review`. Plugin updates arrive through the marketplace.

### Option 2: Personal skill (all your projects)

```bash
git clone https://github.com/alimehr/claude-skill-auditor.git
mkdir -p ~/.claude/skills
cp -r claude-skill-auditor/plugins/skill-auditor/skills/skill-security-review ~/.claude/skills/
```

Run it as `/skill-security-review`.

### Option 3: One project only

```bash
cd /path/to/your/project
mkdir -p .claude/skills
cp -r /path/to/claude-skill-auditor/plugins/skill-auditor/skills/skill-security-review .claude/skills/
```

### Option 4: Claude apps (claude.ai, Claude Desktop, Cowork)

Zip the `skill-security-review` folder (the folder itself, with `SKILL.md` at its top level) and upload it from the Skills section of your Claude settings.

```bash
cd claude-skill-auditor/plugins/skill-auditor/skills
zip -r skill-security-review.zip skill-security-review
```

In the Claude apps the review works on what Claude can reach there (for example an uploaded folder or a public GitHub repo). The install step is designed for Claude Code, where skills live in `.claude/skills/`.

### Requirements

- `git` to review skills from GitHub.
- Python 3.8+ for the bundled scanner (optional; the skill falls back to `grep` if Python is missing).
- No packages, no network access for the scanner, nothing to build.

---

## Usage

Give it a GitHub URL or a local path:

```text
/skill-security-review https://github.com/someone/their-skills
/skill-security-review https://github.com/someone/their-skills/tree/main/skills/pdf-tools
/skill-security-review ~/Downloads/cool-skill
```

Natural language works too, because the skill can also activate from context:

```text
Can you vet this skill before I use it? https://github.com/someone/cool-skill
```

What happens:

1. Claude clones the skill to `~/skill-review/<name>` and records the commit hash.
2. If the repo holds several skills or is a plugin, Claude lists them and asks which to review.
3. Claude runs the scanner, reads every file, and writes the report.
4. **Claude stops.** Read the report, ask questions, ask for edits.
5. When you are happy, say something like *"Approved. Install it in ~/code/my-app"*.

> [!TIP]
> Run it in a fresh chat, and keep the review chat separate from your normal work chats. That keeps the untrusted skill's text out of your other conversations.

---

## What gets checked

| Area | Examples of what Claude looks for |
| --- | --- |
| **Activation** | How broad the `description` is; whether it can run without being called; `paths` limits |
| **Pre-approved power** | `allowed-tools`, `hooks`, `context: fork`, `agent`, `model`, `shell` in the frontmatter |
| **Network** | `curl`, `wget`, HTTP libraries, raw sockets, webhooks, paste sites, URL-encoded data |
| **Code execution** | `eval`, `exec`, `subprocess`, `shell=True`, `bash -c`, `curl ... \| sh` |
| **Secrets** | `~/.ssh`, `~/.aws`, `.env`, keychains, git credentials, API key and token variables |
| **File system** | Paths outside the project: `$HOME`, `/etc`, `/Users`, `%APPDATA%` |
| **Destructive** | `rm -rf`, `sudo`, `chmod 777`, `mkfs`, `dd` |
| **Persistence** | Shell profiles, cron, launch agents, Claude `settings.json`, `CLAUDE.md`, other skills, hooks |
| **Installs** | `pip install`, `npm install`, `npx -y`, `brew install`, unpinned versions |
| **Obfuscation** | base64, `fromCharCode`, hex strings, long encoded blobs, minified code |
| **Prompt injection** | "Ignore previous instructions", "don't tell the user", "without asking", fake system prompts |
| **Hidden content** | Zero-width and bidi characters, Unicode tag characters, HTML comments in Markdown |
| **Unreviewable files** | Binaries, archives, symlinks (especially pointing outside the folder), very large files |
| **Plugins** | Hooks, MCP servers, agents, commands and `bin/` executables, not just the skills |

Each hit is checked in context. A network call in a "web research" skill is expected. The same call in a "format my code" skill is a red flag.

---

## The report

Every review ends with the same structure:

1. **Source**: URL or path, commit hash, date.
2. **What it does**: step by step, in plain language.
3. **When it activates**.
4. **What access it needs**: tools, network destinations, files, installs, hooks.
5. **Findings** with `file:line`, grouped as *red flags*, *worth knowing* and *harmless*.
6. **Not fully reviewed**: anything Claude could not read.
7. **Risk level**:
   - **Low**: instructions or simple local scripts; no network, secrets or writes outside the project; nothing unread.
   - **Medium**: network or installs that fit the purpose, broad triggers, or pre-approved tools; nothing hidden.
   - **High**: hidden or obfuscated content, credential access, unexplained data leaving the machine, persistence, prompt injection, or files that could not be reviewed.
8. **Recommendation**: install as-is, install after specific edits, or do not install.

See a full example in [docs/example-report.md](docs/example-report.md).

---

## How installing works

Only after you approve, and only to the project you name:

- Installs to `<project>/.claude/skills/<skill-name>/`. Never to your personal `~/.claude/skills/` unless you explicitly ask.
- Stops if a skill with the same name already exists there.
- Checks the quarantine copy has not changed since the review (same commit, no local edits).
- Copies the files exactly as reviewed, without `.git`.
- Adds `disable-model-invocation: true` so the skill **only runs when you call it** with `/<skill-name>`.
- Applies any edits you approved, and shows you the diff.
- Shows the final frontmatter and file list, then asks whether to delete the quarantine copy.

**Updating an installed skill?** A new version is treated as a new skill: quarantined, diffed against what you have, reviewed line by line, and installed only after you approve again.

---

## The scanner on its own

`scripts/scan.py` is a standalone, read-only triage tool. Standard library only; no network, no execution of the scanned files.

```bash
python3 plugins/skill-auditor/skills/skill-security-review/scripts/scan.py ~/skill-review/some-skill
python3 plugins/skill-auditor/skills/skill-security-review/scripts/scan.py ~/skill-review/some-skill --format json
```

It prints: a file inventory, parsed `SKILL.md` frontmatter with notes, file-level flags (binary, archive, symlink, hidden, executable, long lines, media), and pattern matches with `file:line`, severity and category.

Expect noise. Security-related skills (including this one) mention `rm -rf` or `curl` in their own text. The scanner points; Claude and you decide.

---

## Limitations

- **Not a guarantee.** Claude can miss things, especially in large or deliberately obfuscated code. A clean report lowers risk; it does not remove it.
- **Prompt injection targets the reviewer too.** The skill tells Claude to treat reviewed files as data, never instructions, and to report any instruction aimed at it. That is a strong defense, not a perfect one.
- **Point in time.** A review covers one commit. Anything pulled later needs a new review.
- **Runtime behavior isn't observed.** Nothing is executed, so code that downloads more code at runtime is flagged by its pattern, but what it would download is unknown.
- **Binaries and archives are not unpacked.** They are reported as unreviewed and raise the risk level.
- **Pattern lists are English-centric.** Injection phrased in other languages is caught by Claude's reading, not by the scanner.

---

## FAQ

**Does it run anything from the skill I'm reviewing?**
No. The procedure forbids running any of the reviewed skill's scripts, installs or setup steps. The only thing executed is this repo's own read-only scanner and standard tools like `git clone`, `find` and `grep`.

**Why "manual-only" after install?**
So the skill cannot activate in chats where you didn't intend it. You call it when you want it with `/<skill-name>`. You can remove the `disable-model-invocation` line later if you want auto-activation.

**Why not install to `~/.claude/skills/`?**
That makes the skill available in every project. Installing per project keeps a reviewed skill where you decided to use it.

**Can it review whole plugins?**
Yes. For plugins it also reviews hooks, MCP server definitions, agents, commands and `bin/` executables.

**Does this skill itself auto-activate?**
Yes, when you ask Claude to review or vet a skill. If you'd rather call it manually, add `disable-model-invocation: true` to its frontmatter.

**Can I use the report for someone else's skill in my company?**
Yes, but treat it as one input to your own security process, not a sign-off.

---

## Repository layout

```text
.
├── .claude-plugin/
│   └── marketplace.json          # makes this repo a Claude Code plugin marketplace
├── plugins/skill-auditor/
│   ├── .claude-plugin/plugin.json
│   └── skills/skill-security-review/
│       ├── SKILL.md              # the review procedure
│       └── scripts/scan.py       # read-only static scanner (stdlib only)
├── docs/
│   ├── how-it-works.md           # design and threat model
│   └── example-report.md         # what a finished review looks like
├── tests/test_scan.py            # scanner tests (fixtures built at test time)
├── CHANGELOG.md · CONTRIBUTING.md · SECURITY.md
└── LICENSE · NOTICE              # Apache-2.0
```

Run the tests:

```bash
python3 -m unittest discover tests -v
```

---

## Contributing

Issues and pull requests are welcome, especially new risky patterns, false-positive fixes, and real-world bypasses. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Found a way to get a malicious skill past the review, or a problem in this repo? Please see [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE). Copyright 2026 [alimehr](https://github.com/alimehr).

This project is not affiliated with or endorsed by Anthropic. "Claude" is a trademark of Anthropic.
