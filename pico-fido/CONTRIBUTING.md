# Contributing

Thank you for your interest in contributing to this project.

This repository is published under AGPLv3

By opening a pull request, you agree to all of the following:

1. **You have the right to contribute this code.**
   You are either the original author of the contribution, or you have obtained the necessary rights/permissions to contribute it under these terms.

2. **Licensing.**
   You agree that your contribution may be:
   - merged into this repository, and
   - used, copied, modified, sublicensed, and redistributed under the AGPLv3

3. **Attribution.**
   The maintainers may keep or add attribution lines such as
   `Copyright (c) <your name>` or an AUTHORS / CONTRIBUTORS list.
   The maintainers may also make changes for clarity, style, security, refactoring,
   or integration reasons.

4. **No automatic SLA.**
   Submitting a pull request does *not* create any support obligation,
   service-level agreement, warranty, or guarantee that the contribution
   will be reviewed, merged, or maintained.

If you are not comfortable with these terms, **do not open a pull request yet.**
Instead, please open an Issue to start a discussion.

## How to contribute (technical side)

### 1. Bug reports / issues
- Please include:
  - hardware / board revision
  - firmware / commit hash
  - exact steps to reproduce
  - expected vs actual behavior
  - logs / traces if available (strip secrets)

Security-sensitive findings: do **not** post publicly.
Send a short report by email instead so it can be triaged responsibly.

### 2. Small fixes / minor improvements
- You can open a PR directly for:
  - bug fixes
  - portability fixes / new board definitions
  - clarifications in code comments
  - build / tooling cleanup
  - documentation of existing behavior

Please keep PRs focused (one logical change per PR if possible).

### 3. Larger features / behavior changes
- Please open an Issue first and describe:
  - what problem you're solving (not just "add feature X")
  - impact on existing flows / security model
  - any new dependencies

### 4. Coding style / security posture
- Aim for clarity and small, auditable changes. This code runs in places
  where secrets live.
- No debug backdoors, no "just for testing" shortcuts left enabled.
- Keep external dependencies minimal and license-compatible
  (MIT / Apache 2.0 / similarly permissive is usually fine).

### 5. Commit / PR format
- Use descriptive commit messages ("Fix PIN retry counter wrap" is better than "fix stuff").
- In the PR description, please include a short summary of what was changed and why.
- At the bottom of the PR description, **copy/paste and confirm the licensing line below**:

  > I confirm that I have read `CONTRIBUTING.md` and I agree to its terms

A PR without that confirmation may be delayed or closed without merge.

## Thank you

This project exists because people build on it, break it, fix it,
and push it into places it wasn't originally designed to go.

Whether you are here for research, hacking on hardware,
rolling out secure keys for a team, or building a commercial product:
thank you for helping improve it.
