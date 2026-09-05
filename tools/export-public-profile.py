"""Convert the public hardware proof profile to the native parser's format."""
import json
import struct
import argparse
from pathlib import Path
from fido2 import cbor

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--second-key", action="store_true")
arguments = parser.parse_args()
prefix = "second-" if arguments.second_key else ""
profile = json.loads((root / f"artifacts/{prefix}test-credential.json").read_text())
if profile["rp"] != "sovereign-windows-auth.local" or profile["version"] != 1:
    raise ValueError("Unexpected profile")
credential = bytes.fromhex(profile["credential_id"])
key = cbor.decode(bytes.fromhex(profile["public_key_cbor"]))
if key[1] != 2 or key[3] != -7 or key[-1] != 1:
    raise ValueError("Expected an ES256 P-256 public key")
public = key[-2] + key[-3]
salt = bytes.fromhex(profile["salt"])
if len(public) != 64 or len(salt) != 32 or not 16 <= len(credential) <= 2048:
    raise ValueError("Invalid public profile length")
(root / f"artifacts/{prefix}public-profile.swt").write_bytes(
    b"SWT\x01" + struct.pack("<I", len(credential)) + credential + public + salt
)
print("Exported public credential handle, public key, and salt. No secrets.")
