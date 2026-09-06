# Troubleshooting

Start with [recovery](RECOVERY.md) if sign-in is affected. Determine whether you
installed only the provider or also enabled the optional desktop restriction.

| Symptom | Next step |
| --- | --- |
| Sovereign does not appear in Sign-in options | Use ordinary Windows sign-in in the default setup. Confirm installation finished and review its private status report. Building alone does not install the tile. |
| Windows chooses PIN or face automatically | In the default setup, select **Sign-in options → Sovereign key → Sign in**. Those alternatives remain available by design. |
| The key does not respond | Connect only one enrolled YubiKey directly to USB, then retry the Sovereign tile. Check that it is the enrolled key; browser passkeys are separate credentials. |
| Touch succeeds but Windows rejects sign-in | Use the recovery route for your setup. A changed Windows PIN or a Windows update can make the bridge fail. Preserve the profile and record the error. |
| Enrollment says a profile already exists | Stop enrollment and preserve the existing files. Automatic replacement and PIN rotation are not implemented. |
| Build cannot find CMake or the FIDO SDK | Follow [setup prerequisites](SETUP.md#prerequisites), install the Visual Studio C++/CMake components, and run the pinned dependency fetch step. |
| Recovery cannot see the Windows installation | Recovery drive letters can differ. Confirm the volume is accessible through the device's existing storage/encryption recovery process; the tool does not unlock BitLocker. |
| Recovery rejects the USB | Use the paired drive with its original credential. Do not pair again or replace the verifier as a troubleshooting step. |

## When the desktop restriction is active

A missing or broken Sovereign provider does not restore PIN/password options
automatically. Boot the paired USB and follow
[Restore PIN sign-in](RECOVERY.md#with-the-desktop-restriction).

Do not unregister the Sovereign provider while its filter is active. Restore
ordinary sign-in first; otherwise the remaining filter can leave no usable tile.

## Report a non-sensitive failure

Use the [bug report form](https://github.com/VrtxOmega/sovereign-windows-auth/issues/new?template=bug_report.yml).
Include:

- Source revision and Windows edition/build.
- Key model/firmware, if known; omit serial numbers.
- Default setup or optional desktop restriction.
- Exact steps, expected behavior, observed behavior and a redacted error code.
- Whether normal sign-in or paired recovery restored access.

Do not upload raw `artifacts/`, `ProgramData\SovereignWindowsAuth`, enrollment
profiles, `recovery.key`, account identifiers or memory dumps. Review any diagnostic
text before sharing it. Vulnerabilities belong in the
[private reporting channel](../SECURITY.md).
