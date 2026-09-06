# Contributing to Sovereign Windows Auth

Contributions are welcome under GPL-3.0-only. Preserve copyright and third-party
attribution. Start with the [architecture](docs/ARCHITECTURE.md),
[security model](docs/SECURITY_MODEL.md) and [roadmap](docs/ROADMAP.md).

## Choose a contribution

- Report results from a new Windows/key configuration using the compatibility form.
- Fix a reproducible build, enrollment, recovery or sign-in problem.
- Improve setup, accessibility, diagnostics or documentation.
- Review credential handling, the PIN bridge or recovery boundaries.

Use [issues](https://github.com/VrtxOmega/sovereign-windows-auth/issues/new/choose)
for non-sensitive work. Send vulnerabilities through [private reporting](SECURITY.md).
For a substantial design change, describe the use case and recovery implications
before developing a large patch.

## Development workflow

1. Fork the repository and create a focused branch from `main`.
2. Follow [setup prerequisites](docs/SETUP.md#prerequisites).
3. Build and run the checks relevant to the change.
4. Update documentation when behavior or validation changes.
5. Open a pull request explaining the problem, resulting behavior and actual checks.

The full local CI-equivalent build is:

```powershell
./tools/fetch-dependencies.ps1
./tools/check-source.ps1
./tools/check-docs.ps1
./tools/build.ps1 -WithVmFilter -WithDesktopFilter
```

This compiles the native components and runs ten suites. It does not enroll keys,
register providers/filters, request credentials or change Windows preferences.
Keep those operations out of CI.

For documentation-only work, run source and documentation checks. For native
changes, run the full build. New or changed sign-in behavior also requires the
appropriate disposable-VM and physical tests; a native test host does not prove
actual LogonUI behavior.

## Review expectations

Keep commits focused. Authentication changes should address cancellation, expiry,
single-use proof handling, account binding, cleanup and the Windows callback
lifecycle. Filter changes should describe affected scenarios, other-account
behavior and independent recovery. Setup changes should cover partial failure
and preservation of existing enrollment.

State what was not tested. Record Windows build, source revision and key
model/firmware for hardware results; do not infer reboot or offline behavior from
ordinary lock/unlock. Use the categories in [validation](docs/VALIDATION.md).

## Keep private material out of contributions

Never commit enrollment profiles, PINs, passwords, recovery credentials, account
identifiers, key serials, memory dumps or unreviewed logs. The ignored
`artifacts/` and `build/` directories are local working data, not publication
inputs. Review every attachment and the staged diff before sending it.

Historical update helpers remain for traceability, not as a general upgrade
procedure. Use the documented setup entry points rather than replaying scripts
from the original development machine.
