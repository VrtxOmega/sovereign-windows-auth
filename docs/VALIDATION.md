# Validation record

## Confirmed on 2026-09-05

Test environment: Windows 11 Pro x64 build 26200; personal Microsoft account;
existing numerical Windows Hello PIN; two independently enrolled physical
YubiKeys. One key was identified as a YubiKey 5C NFC FIPS with firmware 5.4.3.
The second key's exact model/firmware is not asserted here. Serial numbers,
account identifiers and private enrollment artifacts are omitted.

| Check | Evidence and result |
| --- | --- |
| Native build | MSVC v143, Windows SDK 26100; warnings treated as errors; passed |
| Automated suites | Crypto/parser, provider contract, Windows identity format: 3/3 passed |
| Independent key protection | Both keys independently decrypted the same dummy native fixture |
| Account authentication | Both keys independently produced credentials accepted by Windows for the enrolled user |
| SYSTEM context | Exact provider serialization accepted under SYSTEM after a real key touch |
| Completed-proof cancellation | Real touch followed by deselection could not authorize login after refresh/reselection |
| Desktop key 1 and key 2 | User confirmed both physical keys unlocked the actual desktop without PIN entry or facial scan |
| Windows success results | `ReportResult` status/substatus zero at 22:55:26.772Z and 22:56:21.408Z |
| Offline desktop unlock | User confirmed both keys worked with networking disconnected; corresponding successful Windows results at 23:20:30.661Z and 23:20:42.173Z |
| Sleep/resume unlock | User confirmed both keys after separate sleep/wake cycles; Kernel-Power events 506/507 and successful Windows results at 23:21:44.150Z and 23:22:08.929Z corroborate Modern Standby resume |
| First sign-in after restart | User confirmed each key after its own restart; separate Kernel-General startup events at 23:27:11Z and 23:28:18Z precede successful Windows results at 23:27:41.912Z and 23:28:48.028Z |
| Recovery availability | Native PIN remained enabled and had been used successfully during earlier lock-screen tests |

The installed provider for these desktop results has SHA-256:

```text
6837A531335116774093BF17DDDE8E49E43271CF2DB642E0E6BBDF53E1705F92
```

It is preserved locally with the `prototype-2026-09-05` source tag. This hash
identifies the tested local DLL; it does not imply reproducible binaries across
different compiler environments. The project does not publish that local binary
checkpoint, enrollment data or raw logs as a release.

Restart verification used the same installed DLL hash and Windows build 26200.
These were two separate Windows restarts and first sign-ins, not merely session
locks. Full shutdown/power-on, hibernation and offline first sign-in after restart
are separate scenarios and have not been established by these results.

The portable setup was additionally checked with a fresh SDK download, a clean
local build and a new Python environment. The first public
[GitHub Windows CI run](https://github.com/VrtxOmega/sovereign-windows-auth/actions/runs/33998381030)
passed source checks, dependency verification and all three native suites at
revision `92d492bf55ad9e0f11d5877c34e17eed7de0623e`. PowerShell scripts also parsed
successfully in Windows PowerShell 5.1 and PowerShell 7. CI ran on Windows Server
2022; this establishes build/test portability, not Server desktop-login support.

## The display-refresh defect

The first tile lacked the logo/label fields Windows uses for sign-in options.
After correcting visibility, the completion path still lost a successful touch.
The real lock-screen trace showed:

```text
KeyProofReady -> credential UnAdvise -> GetCredentialCount -> credential Advise
```

The original `UnAdvise` called `SetDeselected`, erasing the proof during Windows'
own UI refresh. The fix keeps the proof across callback detachment while retaining
invalidation for actual deselection. The host reproduces the observed refresh
order, and a separate real-key negative test checks cancellation of a completed
proof. Actual desktop unlock then passed with each key.

## Filter and recovery experiment, 2026-09-06 UTC

The separate `swa_filter_lab` experiment subsequently passed its native contract
suite alongside all three existing suites. It covers passive modes, missing
preconditions, unsupported scenarios/flags, known/unknown providers, existing
exclusions, absent/unavailable Sovereign, invalid input, COM identity and remote
credential rejection. This process never registers a filter or changes sign-in.
The subsequent optional QEMU DLL and private-hive recovery suite bring the native
total to six passing suites. The DLL contract test loads the module without
registration or enrollment and verifies COM lifetime, passive operation on an
unconfigured/physical host and rejection of remote credential forwarding.
The recovery suite uses a real private registry hive to verify exact-key removal,
preservation of neighboring filter/provider/COM markers, repeat execution,
unexpected-child refusal and persistence after reopening. The recovery executable
also refused to operate from the working physical Windows desktop.

A disposable Windows 11 Pro x64 build 26200 guest, with Secure Boot and TPM ready,
then exercised the actual sign-in process. A missing provider DLL was omitted
from Windows' filter list and preserved ordinary password sign-in. A loadable
provider returning no credentials triggered five known-provider exclusions and
left no usable sign-in tile. WinPE recovery removed only the filter registration;
the ordinary password tile returned and sign-in reached the desktop. A replay
from the saved broken state returned exit code zero and confirmed preservation
of the stock PIN/password, Sovereign provider and filter COM registrations.

These are real VM recovery results. They do not establish hidden-PIN compatibility
with the real key bridge, encrypted-volume recovery or physical-PC activation.
No physical key or enrollment was attached to the VM. Details, the initial lab
reporting defect and the recovery artifact hash are recorded in
[offline filter recovery](FILTER_RECOVERY.md).

## Next manual checks

Record each result with build number, source revision, key model/firmware and
whether PIN/face fallback was used. Keep a tested recovery route available.

- [x] Unlock each key while network access is disabled, then restore networking.
- [x] Sleep/resume and unlock with each key.
- [x] Restart, then perform first sign-in with each key in separate runs.
- [ ] Start with no key connected; confirm bounded failure and native PIN recovery.
- [ ] Insert an unrelated key; confirm no successful Sovereign authentication.
- [ ] Validate fresh setup and recovery on an additional PC.
- [ ] Revalidate after a Windows update, including the stock PIN callback ABI.

Reboot, offline and sleep results must not be inferred from ordinary Win+L unlock.
CI cannot establish hardware or lock-screen success. Newly published setup
portability changes also need a fresh-machine installation test.
