"""Read-only CTAP inventory. Never requests a PIN or changes the authenticator."""
import json
from pathlib import Path
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2

result = {"operation": "getInfo", "changes_authenticator": False, "devices": []}
try:
    for device in CtapHidDevice.list_devices():
        with device:
            info = Ctap2(device).info
            result["devices"].append({
                "versions": info.versions,
                "extensions": info.extensions,
                "options": info.options,
                "pin_protocols": info.pin_uv_protocols,
                "aaguid": str(info.aaguid),
                "algorithms": info.algorithms,
            })
    result["status"] = "ok" if result["devices"] else "no_accessible_fido_device"
except Exception as exc:
    result.update(status="error", error=type(exc).__name__)
Path(__file__).resolve().parents[1].joinpath("artifacts/key-info.json").write_text(
    json.dumps(result, indent=2), encoding="utf-8"
)
