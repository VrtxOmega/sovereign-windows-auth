# Reporting security issues

This project is experimental. The latest `main` branch is the development target;
there are no supported production releases yet. Read the
[security model](docs/SECURITY_MODEL.md) for the intended trust boundaries.

Private vulnerability reporting is enabled on the upstream repository. Use
GitHub's [**Security → Report a vulnerability**](https://github.com/VrtxOmega/sovereign-windows-auth/security/advisories/new).
If that option is unavailable, open an
issue asking the maintainer for a private reporting channel without including the
vulnerability details. Do not post exploit details involving someone's live
account, enrollment profiles, PINs, passwords, key serials, raw authentication
buffers or memory dumps in public issues.

A useful report includes the affected revision, Windows build, affected security
boundary, required attacker access and a reproduction using synthetic data.
Keep real account material on your own machine.
