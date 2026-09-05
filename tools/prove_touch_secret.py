"""Interactive hardware feasibility test; never reads or stores a Windows password.

Creates ONE non-resident test credential in an isolated RP namespace. Existing
credentials, PIN, OTP configuration, and Windows sign-in are not changed.
Python is used only for this prototype; it cannot guarantee erasure of immutable
secret buffers and is not the intended production logon runtime.
"""
import getpass
import argparse
import hmac
import json
import secrets
import sys
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
from threading import Event, Timer

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fido2 import cbor
from fido2.attestation import Attestation
from fido2.ctap2 import Ctap2
from fido2.ctap import CtapError
from fido2.ctap2.pin import ClientPin
from fido2.hid import CtapHidDevice
from fido2.cose import CoseKey
from fido2.webauthn import AuthenticatorData

RP = "sovereign-windows-auth.local"
ARTIFACTS = Path(__file__).resolve().parents[1] / "artifacts"
PROFILE = ARTIFACTS / "test-credential.json"
REPORT = ARTIFACTS / "touch-proof.json"
results = {"production_ready": False, "windows_login_tested": False, "tests": {}}


def status(phase):
    results["phase"] = phase
    REPORT.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(phase.replace("_", " "), flush=True)


@contextmanager
def deadline(seconds=45):
    event = Event()
    timer = Timer(seconds, event.set)
    timer.start()
    try:
        yield event
    finally:
        timer.cancel()


@contextmanager
def open_key():
    devices = list(CtapHidDevice.list_devices())
    try:
        if len(devices) != 1:
            raise ValueError("Exactly one accessible FIDO key is needed for this test")
        yield Ctap2(devices[0])
    finally:
        for device in devices:
            device.close()


def verify_assertion(assertion, challenge_hash, profile):
    data = assertion.auth_data
    if not hmac.compare_digest(data.rp_id_hash, sha256(RP.encode()).digest()):
        raise ValueError("Wrong relying party")
    if not data.is_user_present():
        raise ValueError("Signed user-presence flag missing")
    if data.is_user_verified():
        raise ValueError("This test specifically requires touch without PIN verification")
    if not assertion.credential or not hmac.compare_digest(
        assertion.credential["id"], bytes.fromhex(profile["credential_id"])
    ):
        raise ValueError("Wrong credential")
    CoseKey.parse(cbor.decode(bytes.fromhex(profile["public_key_cbor"]))).verify(
        data + challenge_hash, assertion.signature
    )


def enroll(ctap):
    if "hmac-secret" not in ctap.info.extensions:
        raise ValueError("Key does not support hmac-secret")
    challenge_hash = sha256(secrets.token_bytes(32)).digest()
    client_pin = ClientPin(ctap)
    token = None
    try:
        if ctap.info.options.get("clientPin"):
            status("waiting_for_one_time_key_PIN_for_test_enrollment")
            print("Enter your EXISTING YubiKey FIDO PIN here, never in chat.")
            print("This is not your Windows password. No automatic PIN retries.")
            pin = getpass.getpass("YubiKey PIN: ")
            try:
                token = client_pin.get_pin_token(pin, ClientPin.PERMISSION.MAKE_CREDENTIAL, RP)
            finally:
                del pin
        status("touch_key_to_create_separate_test_credential")
        with deadline() as event:
            response = ctap.make_credential(
                challenge_hash,
                {"id": RP, "name": "Sovereign Windows authentication proof"},
                {"id": secrets.token_bytes(32), "name": "touch-proof", "displayName": "Touch-only feasibility test"},
                [{"type": "public-key", "alg": -7}],
                extensions={"hmac-secret": True, "credProtect": 1},
                options={"rk": False},
                pin_uv_param=client_pin.protocol.authenticate(token, challenge_hash) if token else None,
                pin_uv_protocol=client_pin.protocol.VERSION if token else None,
                event=event,
            )
    finally:
        del token
    data = response.auth_data
    if data.rp_id_hash != sha256(RP.encode()).digest() or not data.is_user_present():
        raise ValueError("Invalid registration binding or presence flag")
    if (data.extensions or {}).get("hmac-secret") is not True:
        raise ValueError("Key did not enable hmac-secret for the test credential")
    Attestation.for_type(response.fmt)().verify(response.att_stmt, data, challenge_hash)
    credential = data.credential_data
    if credential is None:
        raise ValueError("No credential returned")
    profile = {
        "version": 1, "rp": RP, "credential_id": credential.credential_id.hex(),
        "public_key_cbor": cbor.encode(credential.public_key).hex(),
        "salt": secrets.token_bytes(32).hex(), "resident": False,
        "contains_secrets": False,
    }
    with PROFILE.open("x", encoding="utf-8") as stream:
        json.dump(profile, stream, indent=2)
    results["tests"]["registration_signature_and_rp_verified"] = True
    return profile


def touch_secret(profile, label):
    # A new CTAP connection and ECDH session; NO PIN token survives enrollment.
    with open_key() as ctap:
        client_pin = ClientPin(ctap)
        protocol = client_pin.protocol
        # This protocol operation is public ECDH key agreement, not PIN entry.
        key_agreement, shared_secret = client_pin._get_shared_secret()
        salt_enc = protocol.encrypt(shared_secret, bytes.fromhex(profile["salt"]))
        challenge_hash = sha256(secrets.token_bytes(32)).digest()
        status(label)
        with deadline() as event:
            assertion = ctap.get_assertion(
                RP, challenge_hash,
                allow_list=[{"type": "public-key", "id": bytes.fromhex(profile["credential_id"])}],
                extensions={"hmac-secret": {
                    1: key_agreement, 2: salt_enc,
                    3: protocol.authenticate(shared_secret, salt_enc), 4: protocol.VERSION,
                }},
                # CTAP 2.0 authenticators that omit the `uv` capability reject
                # even uv=false. Omit it there; still require signed UV=false.
                options={"up": True, **({"uv": False} if "uv" in ctap.info.options else {})},
                event=event,
            )
        verify_assertion(assertion, challenge_hash, profile)
        ciphertext = (assertion.auth_data.extensions or {}).get("hmac-secret")
        if not isinstance(ciphertext, bytes):
            raise ValueError("Signed hmac-secret extension absent")
        value = protocol.decrypt(shared_secret, ciphertext)
        if len(value) != 32:
            raise ValueError("Wrong secret length")
        return value, assertion, challenge_hash


def main():
    global PROFILE, REPORT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--second-key", action="store_true")
    arguments = parser.parse_args()
    first_profile = PROFILE
    if arguments.second_key:
        PROFILE = ARTIFACTS / "second-test-credential.json"
        REPORT = ARTIFACTS / "second-touch-proof.json"
    ARTIFACTS.mkdir(exist_ok=True)
    status("starting_hardware_proof")
    if arguments.second_key:
        first = json.loads(first_profile.read_text(encoding="utf-8"))
        with open_key() as ctap:
            try:
                with deadline(5) as event:
                    ctap.get_assertion(
                        RP, secrets.token_bytes(32),
                        allow_list=[{"type": "public-key", "id": bytes.fromhex(first["credential_id"])}],
                        options={"up": False}, event=event,
                    )
            except CtapError as exc:
                if exc.code != CtapError.ERR.NO_CREDENTIALS:
                    raise
                results["tests"]["second_key_does_not_hold_first_key_credential"] = True
            else:
                raise ValueError("The first key is still connected; insert the second key")
    if PROFILE.exists():
        profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        if profile["rp"] != RP or profile["version"] != 1:
            raise ValueError("Unexpected test profile")
    else:
        with open_key() as ctap:
            profile = enroll(ctap)
    first, assertion, challenge = touch_secret(profile, "touch_key_for_first_PIN_free_authentication")
    second, _, _ = touch_secret(profile, "touch_key_for_second_PIN_free_authentication")
    tests = results["tests"]
    tests["signed_presence_without_user_verification"] = True
    tests["secret_reproduced_across_fresh_challenges_and_connections"] = hmac.compare_digest(first, second)
    if not tests["secret_reproduced_across_fresh_challenges_and_connections"]:
        raise ValueError("Hardware secret did not reproduce")
    try:
        verify_assertion(assertion, secrets.token_bytes(32), profile)
    except InvalidSignature:
        tests["replay_under_new_challenge_rejected"] = True
    else:
        raise ValueError("Replayed signature unexpectedly accepted")
    nonce = secrets.token_bytes(12)
    aad = b"Sovereign Windows hardware feasibility test v1"
    plaintext = b"Test data only. This is not a Windows credential."
    encrypted = AESGCM(first).encrypt(nonce, plaintext, aad)
    tests["hardware_secret_decrypts_test_data"] = AESGCM(second).decrypt(nonce, encrypted, aad) == plaintext
    for label, key, payload, binding in (
        ("wrong_key_rejected", secrets.token_bytes(32), encrypted, aad),
        ("tampered_ciphertext_rejected", second, encrypted[:-1] + bytes([encrypted[-1] ^ 1]), aad),
        ("wrong_profile_binding_rejected", second, encrypted, aad + b"tampered"),
    ):
        try:
            AESGCM(key).decrypt(nonce, payload, binding)
        except InvalidTag:
            tests[label] = True
        else:
            raise ValueError(label + " failed")
    del first, second
    status("hardware_proof_passed_windows_login_not_yet_implemented")


if __name__ == "__main__":
    try:
        main()
    except (Exception, KeyboardInterrupt) as exc:
        results["failed_at"] = results.get("phase")
        results["error_type"] = type(exc).__name__
        # CTAP errors contain only a protocol error code; do not log arguments.
        if hasattr(exc, "code"):
            results["ctap_error"] = str(exc.code)
        status("hardware_proof_stopped")
        print("No Windows sign-in change was made. See the safe result report.")
        sys.exit(1)
