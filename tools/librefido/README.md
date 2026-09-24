# librefido-tools

Desktop tools for LibreFido keys, over PC/SC (no administrator rights on
Windows, unlike raw FIDO HID access).

> 安全性和便利性不可兼得，本项目只专注于便利性，请勿存档任何有价值的数据。
> Security and convenience cannot both be had: do not keep anything valuable
> on a LibreFido key.

```bash
pip install "./tools/librefido[gui]"     # PySide6 for the GUI
librefido-gui                            # English or Chinese (system locale, LIBREFIDO_LANG=zh)
librefido --help
```

| Command | What it does |
|---|---|
| `librefido list`, `info`, `health [--scrub]` | devices, security state, profiles, storage health |
| `librefido profile list/select/set/wipe/delete/slots [index]` | isolated profiles (each one a separate key) |
| `librefido export FILE [--no-encrypt] [--pin PIN]` | back up the active profile (touch, FIDO PIN if set); encrypted with a passphrase unless `--no-encrypt` |
| `librefido verify FILE [--device] [--restore-test]` | check a backup without importing it: offline, on the device, or by a full restore into scratch space |
| `librefido import FILE --profile N` | restore or clone a backup into a profile slot |
| `librefido firmware info/update/confirm/rollback` | A/B firmware update with rollback |
| `librefido provision plan / bind-root-key [--apply]` | chip security, see docs/PROVISIONING.md |
| `librefido factory-reset`, `reboot [--bootloader]` | erase everything; restart (or into the ESP32 ROM loader) |

Backup files (`.lfbk`): magic `LFBACKUP`, format version, firmware and
minimum firmware version, profile UUID, payload length and SHA-256, then the
device's backup stream, optionally encrypted with a passphrase (scrypt
N=2^17, r=8, p=1 and ChaCha20-Poly1305 over the header as associated data).
Future firmware keeps reading format 1.

Library use:

```python
from librefido.mgmt import Management
m = Management.open(timeout=5)
print(m.info()["profiles"])
```
