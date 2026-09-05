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
| Recovery availability | Native PIN remained enabled and had been used successfully during earlier lock-screen tests |

The installed provider for these desktop results has SHA-256:

```text
6837A531335116774093BF17DDDE8E49E43271CF2DB642E0E6BBDF53E1705F92
```

It is preserved locally with the `prototype-2026-09-05` source tag. This hash
identifies the tested local DLL; it does not imply reproducible binaries across
different compiler environments. The project does not publish that local binary
checkpoint, enrollment data or raw logs as a release.

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

## Next manual checks

Record each result with build number, source revision, key model/firmware and
whether PIN/face fallback was used. Keep a tested recovery route available.

- [ ] Unlock each key while network access is disabled, then restore networking.
- [ ] Sleep/resume and unlock with each key.
- [ ] Restart, then perform a cold sign-in with each key in separate runs.
- [ ] Start with no key connected; confirm bounded failure and native PIN recovery.
- [ ] Insert an unrelated key; confirm no successful Sovereign authentication.
- [ ] Validate fresh setup and recovery on an additional PC.
- [ ] Revalidate after a Windows update, including the stock PIN callback ABI.

Reboot/offline/sleep results must not be inferred from ordinary Win+L unlock.
CI cannot establish hardware or lock-screen success. Newly published setup
portability changes also need a fresh-machine installation test.
