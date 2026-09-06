# Documentation

Start with [setup](SETUP.md) for a new installation or [recovery](RECOVERY.md)
if you are having trouble signing in. This is an experimental source preview;
the [validation record](VALIDATION.md) identifies the configurations actually tested.

## Install and use

| Guide | Purpose |
| --- | --- |
| [Developer setup](SETUP.md) | Prerequisites, build, two-key enrollment and first installation |
| [Recovery](RECOVERY.md) | Restore access for either sign-in setup and unregister the provider |
| [Troubleshooting](TROUBLESHOOTING.md) | Common symptoms, recovery-first actions and useful reports |
| [Optional desktop restriction](DESKTOP_KEY_REQUIRED.md) | Hide identified ordinary sign-in choices after recovery validation |
| [Paired USB recovery](USB_RECOVERY.md) | Pair a recovery credential and prepare a private bootable recovery screen |

## Understand and contribute

| Guide | Purpose |
| --- | --- |
| [Security model](SECURITY_MODEL.md) | Credential protection, trust boundaries and unsupported scenarios |
| [Architecture](ARCHITECTURE.md) | Runtime flow, source layout and installed components |
| [Validation record](VALIDATION.md) | Current automated, physical and VM results, with remaining gaps |
| [Roadmap](ROADMAP.md) | Engineering priorities and what completion requires |
| [Contributing](../CONTRIBUTING.md) | Development workflow and change validation |
| [Security reporting](../SECURITY.md) | Private vulnerability reports |
| [Changelog](../CHANGELOG.md) | Source milestones and current development |
| [Third-party attribution](../THIRD_PARTY.md) | Dependencies, licenses and implementation references |

## Design and experiment records

These records explain how the current implementation was validated. Their lab
fixtures and historical artifact hashes are not installation instructions.

- [Key-required design](KEY_REQUIRED_DESIGN.md): decisions and required evidence.
- [Hidden PIN bridge experiment](PIN_BRIDGE_VM.md): real Windows LogonUI testing
  with a generated lab PIN.
- [Offline filter recovery](FILTER_RECOVERY.md): exact registry scope, developer
  commands and the original failure/recovery experiment.

Never register the VM fixtures on an ordinary PC. Building them for CI does not
register or activate them.
