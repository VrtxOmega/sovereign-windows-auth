# Roadmap

Priorities are ordered by what makes the project easier to validate, recover and
use on additional machines. This is a development plan, not a release schedule.
See [validation](VALIDATION.md) for completed work.

## 1. Broader compatibility

- Repeat fresh setup, two-key enrollment, unlock and recovery on additional PCs.
- Record Windows edition/build and key model/firmware for each configuration.
- Extend physical testing of the desktop restriction to restart, offline first
  sign-in, sleep, unrelated keys and missing-key behavior.
- Test the Windows PIN callback interfaces after Windows servicing updates.

Completion means documented results with the tested revision and setup, including
failures and any use of fallback. A passing build alone is insufficient.

## 2. Enrollment maintenance

- Change an enrolled Windows PIN without losing access.
- Add or replace a key without discarding working enrollments.
- Revoke one lost key while preserving the other.
- Define rollback and interrupted-update behavior.

Completion requires positive and negative tests for each key, including the
revoked key, plus recovery after a deliberately interrupted update.

## 3. Installation and recovery

- Provide an accessible enrollment and status interface.
- Build a versioned installer with explicit upgrades and uninstall ordering.
- Prepare signed binaries, complete dependency notices and release provenance.
- Validate physical restoration of an active filter and encrypted-volume recovery.
- Make reactivation after recovery an explicit, reviewed operation.

Completion means a fresh-machine installation and an independent recovery test
with an unavailable provider, preserving the existing Windows credential.

## 4. Security review

- Obtain independent review of FIDO verification, profile protection, plaintext
  lifetime, callback ABI, filter scope and USB recovery authorization.
- Review additional-account behavior and interactions with other sign-in software.
- Track remaining findings openly, with vulnerabilities handled privately first.

## Separate research tracks

Disk-encryption interaction, boot artwork and application authentication are
future tracks inspired by the [Linux project](https://github.com/VrtxOmega/yubikey-fido2-linux-auth).
They require their own Windows designs and tests. The current desktop filter
does not implement pre-boot authentication or require a key for UAC or apps.

Contributions are welcome through the [contribution guide](../CONTRIBUTING.md).
