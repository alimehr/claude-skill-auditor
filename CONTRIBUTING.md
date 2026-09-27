# Contributing

Thanks for helping make third-party skills safer to use.

## Good first contributions

- **New risky patterns** for `scan.py`, with a test that shows a real-world shape they catch.
- **False-positive fixes**: a pattern that fires on harmless, common content.
- **Bypasses**: a skill layout or trick that gets past the review. If it is a serious bypass, please follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
- **Docs**: clearer wording, translations of the README, more example reports.

## Ground rules

- The scanner stays **standard-library only**, **read-only**, and **offline**. No imports that open the network or run processes (the tests check this).
- Never execute, import or evaluate scanned files.
- Test fixtures are built in a temp folder at test time. Do not commit files that look like working malicious skills.
- Keep `SKILL.md` portable: only the frontmatter fields `name`, `description`, `license`, `compatibility` (and `metadata` if needed), so it can be uploaded to the Claude apps as well as used in Claude Code.

## Development

```bash
git clone https://github.com/alimehr/claude-skill-auditor.git
cd claude-skill-auditor
python3 -m unittest discover tests -v
```

If you have Claude Code installed, also validate the plugin files:

```bash
claude plugin validate .
claude plugin validate ./plugins/skill-auditor
```

To try your local copy in Claude Code:

```bash
claude plugin marketplace add ./
claude plugin install skill-auditor@claude-skill-auditor
```

## Pull requests

1. One focused change per PR.
2. Add or update tests for scanner changes.
3. Update `CHANGELOG.md` under an `Unreleased` heading.
4. For behavior changes to the review procedure, explain the threat it addresses.

By contributing you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
