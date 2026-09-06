# Developer setup

[Documentation index](README.md) · [Recovery](RECOVERY.md) · [Troubleshooting](TROUBLESHOOTING.md)

This source release has been validated on one Windows 11 Pro x64 PC with two
YubiKeys. It does not yet provide a signed end-user installer. Begin on a machine
where you can recover through the ordinary Windows PIN option, and read the
[security model](SECURITY_MODEL.md) and [recovery guide](RECOVERY.md).

## Prerequisites

- Windows x64, currently tested on Windows 11 Pro build 26200.
- A personal Microsoft account linked to the Windows user, with an existing
  numerical Windows Hello PIN. Current enrollment requires this account type.
- Two USB YubiKeys supporting FIDO2 `hmac-secret`. Runtime selection currently
  filters for Yubico devices. Other vendors and key models are not validated.
- Visual Studio 2022 C++ Build Tools with MSVC v143, CMake 3.24 or later and a Windows SDK.
  SDK 26100 was used for the desktop-tested build.
- Python 3.11 or later and Git, available from the command line.

Use your own account's elevated 64-bit PowerShell for hardware enrollment and
installation. Do not elevate as a different administrator: enrollment binds to
the current Windows user's identity. Never put any PIN or password in a command,
issue, chat, transcript or recording.

## Build without changing sign-in

Clone the repository, then build from its root in PowerShell:

```powershell
git clone https://github.com/VrtxOmega/sovereign-windows-auth.git
cd sovereign-windows-auth
./tools/fetch-dependencies.ps1
./tools/check-source.ps1
./tools/build.ps1
./tools/setup-python.ps1
```

If `python.exe` is not on PATH, supply its location with `-Python` to the setup
script. If PowerShell blocks these reviewed local scripts, use a process-only
policy exception for this terminal, not a machine-wide policy change:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

The SDK script verifies a pinned archive hash and four Yubico-signed runtime DLLs.
The build finds CMake through PATH or Visual Studio's installer inventory and runs
six native test suites. No enrollment, registration or Windows preference changes
are made by those build commands. Build outputs are in `build/Release`.

For the full ten-suite CI configuration, build with both optional components:

```powershell
./tools/build.ps1 -WithVmFilter -WithDesktopFilter
```

These switches compile the desktop filter and VM fixtures; they do not register
or activate them. Never register a VM fixture on an ordinary PC.

## Create the two independent hardware credentials

In an elevated terminal, connect only the first YubiKey and run:

```powershell
./tools/run-hardware-proof.ps1
```

The local console may ask once for that key's existing FIDO PIN during credential
creation. It then asks for touches to verify PIN-free assertions and exports
`artifacts/public-profile.swt`. This key PIN is distinct from your Windows PIN.
The scripts create separate non-resident FIDO credentials for this project and
do not reset the authenticator or modify browser passkeys.

Disconnect the first key, connect only the second key, and run:

```powershell
./tools/enroll-second-hardware-key.ps1
```

This produces `artifacts/second-public-profile.swt` and checks that the second key
does not satisfy the first key's credential. Stop if either script fails. A proof
tool's internal `windows_login_tested: false` refers to that tool's limited scope;
the hardware proof alone does not test Windows login.

## Bind the existing Windows PIN and verify both keys

```powershell
./tools/enroll-pin-and-verify.ps1
```

Enter the numerical PIN used to unlock this PC in the clearly labeled masked
local dialog. Follow prompts to swap and touch both keys. The tool validates the
PIN against Windows before saving its independent encrypted wraps. It then
verifies the saved profile, both keys' exact Windows credential serialization and
cancellation. It saves a private validation receipt only after the checks pass.

The script never overwrites an existing enrollment. If it fails after saving the
profile, keep the result and investigate; do not delete it or rerun enrollment
blindly. The old `enroll-and-verify.ps1` uses an experimental password route and is
not part of this PIN-based setup.

## Register the tested build

```powershell
./tools/install-provider.ps1
```

The installer requires both-key validation for this account and unchanged binary
hashes. It installs into Program Files with restricted write permissions, checks
the copied provider and registers the Sovereign tile. It refuses an existing
installation. It does not disable Windows PIN or face sign-in, install a filter,
or require a reboot. Review the installed recovery script before the first test.

Use **Win+L → Sign-in options → Sovereign key → Sign in**, then touch the key.
Repeat with only the second key connected. If face sign-in is selected, explicitly
select Sovereign for this test. Keep native PIN available. See
[the validation matrix](VALIDATION.md) for further manual checks.

`prepare-native.ps1`, `install-touch-handoff.ps1`, `update-provider-display.ps1`
and `update-provider-refresh.ps1` are historical development helpers with
prerequisites from the original machine's staged updates. They are not a fresh
installation or general upgrade procedure. The current source already includes
the display and refresh fixes; do not replay those updates.

## Optional desktop restriction

After the default provider works with both keys, the separate
[desktop restriction guide](DESKTOP_KEY_REQUIRED.md) covers hiding ordinary
sign-in choices. First prepare and physically boot-test the
[paired USB recovery screen](USB_RECOVERY.md). Activation requires reviewed
account/provider coverage and hashes for the tested artifacts.

This is a bounded developer procedure, not part of the default installation.
Do not remove the underlying PIN enrollment or the stock PIN provider's COM
registration; Sovereign continues to use them internally.
