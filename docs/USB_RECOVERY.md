# Paired USB recovery

This experimental recovery path restores the ordinary Windows sign-in choices.
It does not sign in, reveal or reset a PIN. The user must know their existing PIN.
The working provider and YubiKey enrollments are preserved.

## How the recovery USB works

An administrator pairs one removable drive from the working Windows desktop:

```text
swa_filter_recovery.exe --pair-usb E:\SovereignRecovery
swa_filter_recovery.exe --check-usb E:\SovereignRecovery\recovery.key
```

The directory must already exist. Pairing refuses an existing credential file or
existing pairing record; it does not silently rotate either. A failed partial
pairing requires diagnosis before retrying. These commands do not install the
filter, change enrollment, or change disk encryption.

The tool generates 48 random bytes, prepends an eight-byte version header and
writes the 56-byte `recovery.key` exclusively to the removable drive. It flushes
and reads the file back before storing a SHA-256 verifier in
`HKLM\SOFTWARE\SovereignWindowsAuth\RecoveryUsb`. The registry record is restricted
to SYSTEM and administrators. No PIN is placed on the USB. Credential bytes must
never enter Git, logs, issue attachments or a published recovery image.

This is a copyable bearer credential, not a hardware-bound secret. Drive labels
and serial numbers are not authentication. Someone who copies `recovery.key` to
another removable drive has copied the recovery capability. Keep the USB apart
from the laptop. The program rejects non-removable paths and reparse points, but
those path checks do not provide cryptographic anti-cloning protection.

## Bootable screen

Build `swa_recovery_screen.exe` and `swa_filter_recovery.exe` with the regular
MSVC/CMake build. Both use the static C++ runtime and Windows system libraries.
The screen runs only in Windows PE/RE, finds offline Windows installations and
looks for `SovereignRecovery\recovery.key` on removable drives. It refuses an
ambiguous set of recovery credentials.

1. Boot the recovery media and select the Windows installation if there is more
   than one.
2. Select **Check recovery USB**. This validates the credential against a
   temporary copy of the offline registry without changing that installation.
3. Select **Restore PIN sign-in** and confirm. The tool checks the credential
   again and removes only the Sovereign filter registration.
4. Select **Restart**, remove the USB, and use the existing Windows PIN.

The USB must remain connected through recovery. Removing it or replacing the
credential after the check does not authorize the restore operation. A protected
registry backup is retained on the Windows volume when restoration is attempted.
See [the exact scope of offline recovery](FILTER_RECOVERY.md).

`tools/build_recovery_iso.sh` creates a private recovery ISO from an operator's
Windows x64 ISO and compiled executables. It requires 7-Zip, wimlib and xorriso on
Linux. It exports Windows PE image 1 and uses a
[custom Winpeshl startup](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpeshlini-reference-launching-an-app-when-winpe-starts?view=windows-11).
An optional Intel VMD driver directory supplies `iaStorVD.inf` and its signed
driver files. Verify driver provenance before adding it. The script does not
format media and requires a new output directory. Copy the resulting ISO to an
existing compatible multiboot drive separately. Microsoft binaries, drivers and
private credentials are not part of this source distribution.

## Security boundary and current limits

USB authorization protects this recovery tool's normal workflow. An unencrypted
Windows disk can be edited offline by another administrator or boot environment;
an attacker can replace the verifier, remove the filter or run older recovery
software. Pairing alone cannot make the USB the only possible way around sign-in.
Disk encryption and a tested platform boot/recovery policy are separate necessary
work before claiming protection against offline bypass. This tool does not
unlock BitLocker, change its protectors, or enable Secure Boot.

The program treats an existing but damaged pairing as an error. For legacy
unpaired installations only, the original no-key offline removal command remains
available. Supplying a key or using the graphical check always requires pairing.

No filter is activated on the development laptop by this work. Physical USB boot
and credential verification have now passed. Restoring an active restriction on
that hardware, encrypted-volume recovery and the real provider's hidden-PIN
compatibility remain to be validated before enabling key-required sign-in.

## Validation on 2026-09-06 UTC

MSVC x64 compilation with warnings treated as errors and all seven native suites
passed. A disposable Windows 11 Pro build 26200 VM had its own generated PIN and
a separate emulated removable USB; no real key profiles or physical disks were
attached. The following checks passed:

| Case | Observed result |
| --- | --- |
| First pairing and read-back | Correct credential accepted; only the verifier was stored in Windows. |
| Repeat pairing | Refused; existing pairing was retained. |
| Wrong/missing credential or damaged verifier | Refused. Restoring the lab verifier allowed the correct key again. |
| Broken provider with active filter | Actual LogonUI omitted five known convenience providers and offered no usable tile, despite the enrolled PIN. |
| Boot recovery image without USB / with wrong USB | Restore remained unavailable; explicit rejection appeared. |
| Remove correct USB after checking, before confirming restore | Backend refused; the next successful check confirmed that the filter remained installed. |
| Correct USB and confirmed restore | The screen reported successful exact filter removal and a protected registry backup. |
| Restart with recovery media removed | Stock PIN screen returned; the previously enrolled PIN reached the full desktop. Other provider/COM registrations remained present. |

The Windows virtual power button initially left the VM running with a black
screen. That instance was stopped through QMP and its state preserved; recovery
continued on a separate overlay. This is not evidence of a clean shutdown at that
point. The eventual recovery-screen Restart operation booted Windows successfully.
The first image used an EFI boot prompt, which could time out and boot Windows;
the tested final image uses Microsoft's no-prompt EFI boot image. Regular Segoe UI
was absent from the PE image, so the application uses its included Tahoma font.

Tested local artifact SHA-256 values:

```text
swa_filter_recovery.exe  3b385716eec40043e962e8b5191c0de4b69fc357725fe0464bebf1f4e89e4b83
swa_recovery_screen.exe  f1eec456d136615104e489e80138a3189c45e54095a57c5436cdde64c91ba93d
private recovery ISO     c37f5347525192634d6bfebe1050795970d7627d23862e679e7cc86ff5e55e58
```

These identify test artifacts, not signed releases or reproducible-build claims.

The physical laptop exposed an additional pairing issue: an elevated open of
`SOFTWARE` with read/write access returned Windows error 5, while read/create-child
access succeeded. Pairing now requests only read/create-child access on that
parent; it never needs to set values there. After that correction the physical
Corsair paired successfully and passed read-back verification. The installed
YubiKey provider hash was unchanged and no filter was activated.

The resulting recovery executable is
`9769d776701f0a0d258eb5877436b95def207c7308cd97baf856415e074c320c`.
The rebuilt private ISO is
`964cac8ad47f58335792a46b6ed748947e83257ca3db4f8bc1198146a6c42717`.
All seven native suites passed again. This image also booted in the VM and
verified its existing paired USB, reporting that the filter remained absent.
The offline restoration code and credential format were unchanged by the pairing
access correction. The full removal/PIN-login test above used the earlier hashes.

### Physical Corsair boot check

The user supplied a photograph of the recovery screen running on the physical
laptop after booting the Corsair. The screen found the offline installation at
`E:\Windows`, verified the paired USB for that installation, reported that no
Sovereign sign-in restriction was installed, and completed its check without
changing the offline Windows installation. This confirms physical boot, storage
discovery and USB authorization. Drive letters in recovery can differ from those
in the installed Windows session.

The user subsequently confirmed returning to normal Windows after this check.
The photograph and confirmation establish the read-only recovery boot and return,
not restoration of an active filter on the physical laptop. Physical restoration
with a restriction installed, encrypted-volume recovery and physical hidden-PIN
validation remain pending. The separate [VM bridge test](PIN_BRIDGE_VM.md) has
since passed first sign-in, wrong-PIN rejection and unlock with the standard
tiles hidden; it used a generated local-account PIN rather than real YubiKeys.
