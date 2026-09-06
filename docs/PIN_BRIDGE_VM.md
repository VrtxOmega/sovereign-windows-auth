# Hidden PIN bridge compatibility test

On 2026-09-06, the production `swa::WindowsPin` bridge completed first sign-in
after a restart and a subsequent desktop unlock in a disposable Windows 11
build 26200 VM while the stock PIN/password tiles were filtered out.
An incorrect lab PIN was rejected with `STATUS_LOGON_FAILURE` (`0xC000006D`);
the screen remained locked with no ordinary fallback tile. A deliberate subsequent
attempt with the correct lab PIN reached the desktop.

## What ran

The optional `SovereignPinBridgeVm` fixture links the same `swa_core` library as
the real provider. Its credential invokes `swa::WindowsPin` using LogonUI's real
user array and the selected lab account SID. It does not implement its own
Windows PIN serialization. Like the production provider, it retains the stock
provider bridge until Windows reports the sign-in result.

This fixture accepts a generated **lab PIN** directly, in a masked field labelled
"Lab PIN". It does **not** authenticate a YubiKey, test FIDO rejection, or replace
the production provider's key verification. No real account credentials,
YubiKeys, enrollment profiles, physical disks, or Corsair recovery credential
were attached to the VM.

The fixture is built only with `SWA_BUILD_VM_FILTER=ON` (`tools/build.ps1
-WithVmFilter`). It cannot activate without the QEMU manufacturer string, a
regular `C:\SwaLab\lab-installed.marker`, `BridgeArmed=1`, `Mode=2`, and the
configured lab `BridgeSid`. These are accidental-deployment guards, not an
authentication boundary. Never register this fixture on an ordinary PC.

The VM filter and bridge both recorded their process ID. On first sign-in those
IDs matched LogonUI PID 1112; on unlock/rejection they matched PID 2980. Each
filter invocation reported five known providers excluded from 13 entries,
Sovereign present, and zero usage flags. Successful attempts reported status
and substatus zero. The filter registration and stock PIN/password COM
registrations remained present after successful sign-in. Screenshots confirmed
the dedicated lab tile and the resulting desktop.

Only counts, process IDs, result codes and registration-presence metadata were
collected. PIN values and serialized credentials were not logged. The guest was
shut down through Windows after the test; previous disk/TPM checkpoints were
preserved.

Tested fixture DLL SHA-256:

`6B4B902C48B2070771DC3636F1F120C0E2A9D55A0E1D92E2318E7B2EBA55D28A`

All eight native suites passed, including the fixture's nonactivation and COM
lifetime checks. Those checks load the DLL without registering it and verify
that an unarmed host exposes no credentials or automatic sign-in.

## What remains

This establishes compatibility between filtering the visible PIN tile and using
its provider internally on the tested Windows build and local VM account. It does
not establish physical Microsoft-account compatibility, missing/wrong YubiKey
behavior under a filter, coverage of other installed providers, or protection
against offline changes to an unencrypted disk.

The working physical provider and enrollments are unchanged. A physical key-only
trial still needs a reviewed activation mechanism, account/provider inventory,
and the [recovery requirements](KEY_REQUIRED_DESIGN.md). The paired Corsair has
already passed physical boot and its read-only authorization check; actual
removal of an active filter on the physical laptop remains untested.
