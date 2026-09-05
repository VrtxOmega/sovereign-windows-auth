# Contributing

Contributions are accepted under GPL-3.0-only. Preserve attribution and third-party
notices. Explain the behavior being changed, how it was verified and which checks
remain untested. Keep commits focused; never publish enrollment profiles, account
identifiers, key serials, credentials, memory dumps or unreviewed logs.

Use `tools/build.ps1` for the native build and tests and
`tools/check-source.ps1` for source checks. CI must never enroll a credential,
register a sign-in provider, change system sign-in preferences or request a PIN.

Authentication changes need review of cancellation, expiry, one-time consumption,
account binding, error cleanup and the Windows callback lifecycle. Automated
results alone do not establish real LogonUI behavior. Record manual results using
the categories in [the validation record](docs/VALIDATION.md).

Useful next contributions:

- Reboot/offline/sleep and additional-machine compatibility reports.
- Safe PIN rotation, re-enrollment and individual-key revocation.
- Review of the Windows PIN callback ABI and memory-handling boundaries.
- A recoverable installer and signed releases with complete dependency notices.
- Accessible enrollment UI and clear status/error text.

Open a normal issue for reproducible non-sensitive failures. Use the private
reporting route in [SECURITY.md](SECURITY.md) for vulnerabilities.
