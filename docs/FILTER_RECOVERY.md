# Offline recovery for the filter experiment

This document records the original recovery experiment and the tool's exact
registry scope. Native tests and disposable Windows/WinPE recovery passed on
2026-09-06 UTC. The later [desktop filter](DESKTOP_KEY_REQUIRED.md) has also passed
physical two-key unlock; [USB recovery](USB_RECOVERY.md) records the paired
recovery workflow. Start with [recovery guidance](RECOVERY.md) for an installed PC.

## What recovery removes

The recovery executable removes this one registration from an offline Windows
`SOFTWARE` hive:

```text
Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\{51583B4D-1D80-4692-B4EF-1C385FBCF22D}
```

It does not remove the stock PIN credential, Sovereign's credential provider,
the filter's COM class, encrypted enrollment files or other filters. The deletion
is deliberately non-recursive: unexpected child keys cause an error. If the
registration is already absent, recovery reports that without inventing a change.

## Build and inspect before use

`tools/build.ps1` builds `swa_filter_recovery.exe` with the C++ runtime linked
statically. It needs ordinary Windows system libraries, not the FIDO DLLs, an
enrolled key, a functioning Sovereign DLL or an accessible Windows desktop.

`tools/build.ps1 -WithVmFilter` additionally builds the QEMU-only filter DLL,
its COM test and a deliberately unusable provider fixture. This does not register
them. The filter stays passive on the physical
development machine and cannot be enabled there through configuration. Its QEMU
firmware check is an experiment guard, not an authentication boundary.

Keep a verified copy of the recovery executable on separately accessible recovery
media before any future sign-in restriction. Preserve normal disk encryption and
its existing recovery process. The tool does not unlock encrypted volumes or
change their protectors. The [paired USB extension](USB_RECOVERY.md) checks a
private removable-drive credential before recovery on paired installations.
Legacy unpaired installations retain the original command. Offline write access
still depends on the volume's encryption/recovery route. The lab disk was
unencrypted. Its result does not establish protection
against a person who can already write to the offline Windows disk.

## Offline command

From a matching Windows recovery environment's Command Prompt, identify the
offline Windows volume; its letter may differ from normal Windows. Then run:

```text
E:\swa_filter_recovery.exe --remove-filter C:\Windows
```

The program requires WinRE/WinPE, backup/restore privileges and an explicit local
Windows path. It rejects the running environment's volume and paths traversing
reparse points. Missing hive/kernel files stop the operation before a hive load.

Before loading the original hive, it first inspects a separate temporary copy and
checks any required USB credential. Wrong or missing credentials on a paired
installation stop recovery before any target-volume backup or hive load.
Once authorized, it creates a fresh directory under that offline
Windows installation's `System32\config`, protected for SYSTEM and administrators,
and copies `SOFTWARE` plus available `SOFTWARE.LOG1` and `SOFTWARE.LOG2`. It then
loads the hive under a unique temporary registry mount, checks its Windows
structure, removes the exact registration, flushes it and unloads it. Unload
failures are reported. Successful output gives the backup location.

The backup can contain private system information. Keep it protected; do not
attach it to public issues or copy it into Git. If recovery reports an error,
preserve its message and diagnose that error before editing other registry keys.

## Evidence and limits

The automated suite uses a real, separate registry hive. It checks exact-key
removal, other filter/provider/COM marker preservation, repeat execution,
unexpected-child refusal, persistence after reopening, and fixture cleanup.
A separate invocation on the physical Windows desktop confirmed that offline
recovery refuses to act there. These do not replace a recovery boot test.

The disposable machine runs Windows 11 Pro x64 build 26200 under QEMU 8.2.2/KVM,
with Secure Boot and TPM readiness confirmed inside the guest. It has one private
virtual disk, a generated local lab account and no host disks, USB keys or real
enrollment profiles attached.

Two different provider failures were exercised in actual LogonUI:

| Failure | Observed behavior |
| --- | --- |
| Sovereign registered, DLL missing | Windows passed 12 provider identifiers to the filter, omitting Sovereign. The absent-provider guard excluded none. The ordinary password tile remained available and a lab password sign-in succeeded. |
| Sovereign DLL loads, returns no credentials | Windows passed 13 identifiers including Sovereign. The filter excluded five known convenience providers. The sign-in screen had no usable credential tile. |

In both cases, the process ID recorded by the filter matched the running LogonUI,
and desktop flags were zero. The second case uses
`SovereignUnavailableProviderFixture.dll`: a COM provider that returns zero
credentials and never authenticates. It demonstrates why mere provider presence
cannot establish that a person has a working sign-in route. An independent
recovery boot is still required; an in-session registry edit is insufficient.

### Recovery boot result

From the second failure state, Windows installation media booted WinPE and ran
the standalone recovery executable against the offline Windows directory. The
tool backed up the hive, removed the filter registration and returned success.
After booting Windows, the ordinary password tile was available and the generated
lab password reached the desktop. Recovery was also replayed from a saved copy of
the broken VM with the same executable:

- Recovery exit code: `0`; output confirmed removal of the exact filter registration.
- Filter registration: absent after boot.
- Stock PIN and password registrations, Sovereign provider registration and the
  filter COM class: still present after boot.
- The deliberately unusable Sovereign provider remained installed; recovery did
  not depend on repairing it or supplying a key.

The initial lab wrapper incorrectly redirected its numeric exit-code report,
leaving that report empty. Its placement of output redirection was corrected
before the replay; the recovery executable itself was unchanged. The first run's
removal log and successful desktop sign-in were retained separately.

The tested recovery executable's SHA-256 was
`1d8634e8793821200a9ae59238eb031b28763fb3beb96138ecd91d7195a8987a`.
This identifies the local test artifact, not a signed release or reproducible-build
claim. No registry backup, guest credential or enrollment data is published.

The exercise does not establish hidden-PIN compatibility with the real PIN bridge,
encrypted-volume recovery, or safety for additional accounts.

See the [key-required design](KEY_REQUIRED_DESIGN.md) for those remaining gates.
Registry behavior follows Microsoft's [hive-loading API](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regloadkeyw)
and [private application-hive API](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regloadappkeyw).
