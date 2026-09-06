# Paired USB recovery

The recovery screen restores ordinary Windows sign-in choices after checking a
paired removable credential. It does not sign in, reveal or reset a PIN. Your
existing PIN and Sovereign key enrollments are preserved.

For the short operating procedure, see [recovery](RECOVERY.md#with-the-desktop-restriction).
This page covers preparation, implementation and test evidence.

## Pair a removable drive

Build the project first. From your own account's elevated 64-bit PowerShell,
identify the intended removable USB and create its `SovereignRecovery` directory.
The example below uses **E:**; replace that letter with your verified USB drive.

```powershell
./build/Release/swa_filter_recovery.exe --pair-usb E:\SovereignRecovery
./build/Release/swa_filter_recovery.exe --check-usb E:\SovereignRecovery\recovery.key
```

The directory must already exist. Pairing refuses an existing credential file or
pairing record. A partial failure requires diagnosis before retrying. These
commands do not install a filter, format the USB or change disk encryption.

The tool writes 48 random bytes plus an eight-byte version header to
`recovery.key`, flushes and reads it back, then stores a SHA-256 verifier in
`HKLM\SOFTWARE\SovereignWindowsAuth\RecoveryUsb`. The verifier is restricted to
SYSTEM and administrators. No PIN is placed on the USB.

Keep `recovery.key` private and separate from the laptop. Never put it in Git,
logs, issue attachments or a published ISO. It is a copyable bearer credential:
copying it to another removable drive copies the recovery capability. Labels and
serial numbers do not provide cryptographic anti-cloning.

## Prepare the bootable screen

The regular build produces `swa_recovery_screen.exe` and
`swa_filter_recovery.exe` with a static C++ runtime and Windows system libraries.
The screen runs only in Windows PE/RE, discovers offline installations and looks
for `SovereignRecovery\recovery.key` on removable drives. It rejects ambiguous
sets of recovery credentials.

The Linux builder creates a private recovery ISO from an operator-supplied
Windows x64 ISO and the compiled executables. It requires 7-Zip, wimlib and
xorriso. Replace the example paths with your own files and a new output directory:

```sh
bash tools/build_recovery_iso.sh \
  /path/to/Windows.iso \
  /path/to/build/Release \
  /path/to/new-recovery-output
```

An optional fourth argument is a verified Intel VMD driver directory containing
`iaStorVD.inf` and its signed driver files. The builder exports Windows PE image 1
and uses a [custom Winpeshl startup](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpeshlini-reference-launching-an-app-when-winpe-starts?view=windows-11).

Copy the resulting `Sovereign-Recovery.iso` to an existing compatible multiboot
USB separately. The builder does not format media and refuses an existing output
directory. Windows binaries, storage drivers and private credentials are not
distributed in this repository.

Boot the intended physical PC from the USB and perform its read-only check
before enabling the desktop restriction. Recovery drive letters can differ from
those in the normal Windows session.

## Restore PIN sign-in

1. Boot the recovery image and select the intended Windows installation.
2. Select **Check recovery USB**.
3. Keep the USB connected. Select **Restore PIN sign-in** and confirm.
4. Select **Restart**, remove the recovery USB and use your existing Windows PIN.

The backend checks the credential again before the write. Removing the USB after
verification does not authorize restoration. A protected hive backup is retained
when restoration is attempted. Only the exact filter registration is removed;
the stock PIN, provider COM registrations and encrypted profiles remain.
See [offline recovery scope](FILTER_RECOVERY.md).

## Validation

The disposable Windows 11 Pro build 26200 lab used a generated PIN and its own
emulated removable credential. No physical enrollment or recovery secret was
attached to it.

| Case | Observed result |
| --- | --- |
| First pairing/read-back | Correct credential accepted; Windows stored only its verifier |
| Repeated pairing | Refused without replacing the existing pairing |
| Missing/wrong credential or damaged verifier | Refused |
| Remove USB after check, before restore | Backend refused; filter remained installed |
| Broken provider with active restriction | No ordinary sign-in tile |
| Correct USB and confirmed restore | Exact filter registration removed; protected backup created |
| Restart after ejecting recovery media | Existing PIN reached the full Windows desktop |

The final desktop filter was additionally tested with Sovereign's COM path
deliberately pointing to a missing DLL. Missing-USB recovery was refused; paired
recovery removed the filter; normal PIN sign-in then reached the desktop. This
final replay used the corrected recovery artifacts listed below.

### Physical recovery media

The paired Corsair USB booted the physical laptop, found its offline Windows
installation, verified pairing and completed a read-only check. The owner
confirmed returning to Windows. At that time, no restriction was installed.

The desktop filter was subsequently activated and both physical keys passed
lock/unlock with ordinary PIN/password options hidden. That does not constitute
a physical offline restore test. Actual removal of an active filter on that
laptop and encrypted-volume recovery remain unverified.

### Tested local artifacts

| Artifact | SHA-256 |
| --- | --- |
| Recovery executable | `9769d776701f0a0d258eb5877436b95def207c7308cd97baf856415e074c320c` |
| Recovery screen | `f1eec456d136615104e489e80138a3189c45e54095a57c5436cdde64c91ba93d` |
| Private recovery ISO | `964cac8ad47f58335792a46b6ed748947e83257ca3db4f8bc1198146a6c42717` |

These identify tested local artifacts, not signed public releases or reproducible
builds. Earlier experiment artifacts and intermediate results remain in Git
history. The final image uses Microsoft's no-prompt EFI boot image and the Tahoma
font available in Windows PE. Pairing requests only the parent registry rights
it needs after a physical-PC access-denied issue was corrected.

## Security boundary

USB authorization protects this tool's normal workflow. An unencrypted Windows
volume remains writable from another boot environment: an attacker with that
access can alter the verifier or filter registration. Disk encryption and a
tested platform boot/recovery policy are separate work. The tool does not unlock
BitLocker, change its protectors or enable Secure Boot.

An existing but damaged pairing is an error. Legacy unpaired installations retain
the original no-key command; providing a key or using the graphical check always
requires pairing. Do not interpret this compatibility path as exclusive offline
USB enforcement. [Security model](SECURITY_MODEL.md)
