#!/usr/bin/env python3
"""PyKMIP's client against goose-kmipd: each operation in KMIP 1.2, 1.4 and 2.0.

Run in the gs-pykmip image (scripts/interop.py does), with the host's
network:

    python3 pykmip_client.py HOST PORT CERTS RUN

CERTS holds ca.pem, client.pem and client.key. A line per check, then the
counts; exit 1 on any failure.
"""

import sys

from kmip.core import enums
from kmip.core import objects as core_objects
from kmip.core import primitives
from kmip.core.factories import attributes as attr_factory
from kmip.pie import client as pie
from kmip.pie import exceptions as pie_exceptions
from kmip.pie import objects
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

checks = 0
failures = 0


def check(what, ok):
    global checks, failures
    checks += 1
    if not ok:
        failures += 1
    print(("ok    " if ok else "FAIL  ") + what)


def attempt(what, fn):
    try:
        return fn()
    except Exception as e:  # noqa: BLE001 - every failure is a check's
        check(f"{what}: {type(e).__name__}: {e}", False)
        return None


def run(host, port, certs, version, run_id):
    tag = f"{run_id}-{version.name}"
    c = pie.ProxyKmipClient(hostname=host, port=port, cert=f"{certs}/client.pem", key=f"{certs}/client.key",
                            ca=f"{certs}/ca.pem", config_file="/dev/null", kmip_version=version)
    c.open()
    try:
        # A symmetric key: create, get, attributes, locate, activate.
        name = f"py-aes-{tag}"
        uid = attempt("create", lambda: c.create(enums.CryptographicAlgorithm.AES, 256, name=name,
                      cryptographic_usage_mask=[enums.CryptographicUsageMask.ENCRYPT, enums.CryptographicUsageMask.DECRYPT]))
        check("create gives a Unique Identifier", bool(uid))
        key = attempt("get", lambda: c.get(uid))
        check("get: a 32-byte AES key", key is not None and key.cryptographic_algorithm == enums.CryptographicAlgorithm.AES
              and len(key.value) == 32)
        got = attempt("get attributes", lambda: c.get_attributes(uid, ["State", "Name", "Cryptographic Length"]))
        if got:
            by_name = {a.attribute_name.value: a.attribute_value for a in got[1]}
            check("get attributes: Pre-Active", by_name.get("State") is not None and by_name["State"].value == enums.State.PRE_ACTIVE)
            check("get attributes: the length", by_name.get("Cryptographic Length") is not None and by_name["Cryptographic Length"].value == 256)
            check("get attributes: the name", by_name.get("Name") is not None and by_name["Name"].name_value.value == name)
        names = attempt("get attribute list", lambda: c.get_attribute_list(uid))
        check("get attribute list: State and Name", names is not None and "State" in names and "Name" in names)
        f = attr_factory.AttributeFactory()
        found = attempt("locate by name", lambda: c.locate(attributes=[f.create_attribute(enums.AttributeType.NAME, name)]))
        check("locate finds the key", found == [uid])
        attempt("activate", lambda: c.activate(uid))

        # Encrypt and decrypt, checked against cryptography's AES-CBC.
        if version >= enums.KMIPVersion.KMIP_1_2:
            iv = bytes(range(16))
            params = {"cryptographic_algorithm": enums.CryptographicAlgorithm.AES,
                      "block_cipher_mode": enums.BlockCipherMode.CBC, "padding_method": enums.PaddingMethod.PKCS5}
            enc = attempt("encrypt", lambda: c.encrypt(b"sixteen byte msg plus more", uid=uid,
                          cryptographic_parameters=params, iv_counter_nonce=iv))
            if enc:
                d = Cipher(algorithms.AES(key.value), modes.CBC(iv)).decryptor()
                plain = d.update(enc[0]) + d.finalize()
                check("encrypt: cryptography's AES-CBC decrypts it", plain[:26] == b"sixteen byte msg plus more")
                dec = attempt("decrypt", lambda: c.decrypt(enc[0], uid=uid, cryptographic_parameters=params, iv_counter_nonce=iv))
                check("decrypt: the plaintext again", dec == b"sixteen byte msg plus more")

            # MAC with an HMAC key registered here.
            # Named: PyKMIP names every object "Symmetric Key" when not told,
            # and a server holds Names unique (KMIP 2.1 §4.38).
            hk = objects.SymmetricKey(enums.CryptographicAlgorithm.HMAC_SHA256, 256, b"\x07" * 32,
                                      masks=[enums.CryptographicUsageMask.MAC_GENERATE], name=f"py-hmac-{tag}")
            huid = attempt("register an HMAC key", lambda: c.register(hk))
            attempt("activate the HMAC key", lambda: c.activate(huid))
            m = attempt("mac", lambda: c.mac(b"the data", uid=huid, algorithm=enums.CryptographicAlgorithm.HMAC_SHA256))
            h = hmac.HMAC(b"\x07" * 32, hashes.SHA256())
            h.update(b"the data")
            check("mac: cryptography's HMAC the same", m is not None and m[1] == h.finalize())

            # An RSA key pair: sign, verify.
            pair = attempt("create key pair", lambda: c.create_key_pair(enums.CryptographicAlgorithm.RSA, 2048,
                           public_usage_mask=[enums.CryptographicUsageMask.VERIFY],
                           private_usage_mask=[enums.CryptographicUsageMask.SIGN]))
            if pair:
                pub, priv = pair
                attempt("activate the public key", lambda: c.activate(pub))
                attempt("activate the private key", lambda: c.activate(priv))
                sp = {"cryptographic_algorithm": enums.CryptographicAlgorithm.RSA, "hashing_algorithm": enums.HashingAlgorithm.SHA_256,
                      "padding_method": enums.PaddingMethod.PKCS1v15}
                sig = attempt("sign", lambda: c.sign(b"signed text", uid=priv, cryptographic_parameters=sp))
                if sig:
                    v = attempt("verify", lambda: c.signature_verify(b"signed text", sig, uid=pub, cryptographic_parameters=sp))
                    check("verify: valid", v == enums.ValidityIndicator.VALID)
                    v2 = attempt("verify other data", lambda: c.signature_verify(b"other text", sig, uid=pub, cryptographic_parameters=sp))
                    check("verify other data: invalid", v2 == enums.ValidityIndicator.INVALID)
                pk = attempt("get the public key", lambda: c.get(pub))
                check("get: an RSA public key", pk is not None and pk.cryptographic_algorithm == enums.CryptographicAlgorithm.RSA)

        # Register a secret, get it back.
        sd = objects.SecretData(b"correct horse", enums.SecretDataType.PASSWORD, masks=[enums.CryptographicUsageMask.DERIVE_KEY],
                                name=f"py-secret-{tag}")
        suid = attempt("register secret data", lambda: c.register(sd))
        s = attempt("get the secret", lambda: c.get(suid))
        check("get: the secret's bytes", s is not None and s.value == b"correct horse")

        # Attributes changed.
        if version >= enums.KMIPVersion.KMIP_2_0:
            attempt("set attribute", lambda: c.set_attribute(unique_identifier=suid, attribute_name="Sensitive", attribute_value=False))
            new = core_objects.NewAttribute(attribute=primitives.Boolean(True, tag=enums.Tags.SENSITIVE))
            attempt("modify attribute", lambda: c.modify_attribute(unique_identifier=suid, new_attribute=new))
            got = attempt("get Sensitive", lambda: c.get_attributes(suid, ["Sensitive"]))
            check("modify attribute: Sensitive", got is not None and len(got[1]) == 1 and got[1][0].attribute_value.value is True)
        if version >= enums.KMIPVersion.KMIP_2_0:
            ref = core_objects.AttributeReference(vendor_identification="", attribute_name="Name")
            attempt("delete attribute (Name)", lambda: c.delete_attribute(unique_identifier=uid, attribute_reference=ref))
        else:
            attempt("delete attribute (Name)", lambda: c.delete_attribute(unique_identifier=uid, attribute_name="Name", attribute_index=0))
        got = attempt("get Name", lambda: c.get_attributes(uid, ["Name"]))
        check("delete attribute: gone", got is not None and len(got[1]) == 0)

        # Revoke, destroy.
        try:
            c.destroy(uid)
            check("destroy an Active key refused", False)
        except pie_exceptions.KmipOperationFailure as e:
            # 2.1's Wrong Key Lifecycle State; before 2.1, Permission Denied.
            check("destroy an Active key refused", e.reason in (enums.ResultReason.WRONG_KEY_LIFECYCLE_STATE,
                                                                 enums.ResultReason.PERMISSION_DENIED))
        attempt("revoke", lambda: c.revoke(enums.RevocationReasonCode.CESSATION_OF_OPERATION, uid, "done"))
        got = attempt("get State", lambda: c.get_attributes(uid, ["State"]))
        check("revoke: Deactivated", got is not None and got[1][0].attribute_value.value == enums.State.DEACTIVATED)
        attempt("destroy", lambda: c.destroy(uid))
        try:
            c.get(uid)
            check("get after destroy: Item Not Found or Object Destroyed", False)
        except pie_exceptions.KmipOperationFailure as e:
            # 2.0 has Object Destroyed for it; a destroyed object's attributes stay.
            check("get after destroy: Item Not Found or Object Destroyed",
                  e.reason in (enums.ResultReason.ITEM_NOT_FOUND, enums.ResultReason.OBJECT_DESTROYED))
    finally:
        c.close()


def main():
    host, port, certs, run_id = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
    for v in (enums.KMIPVersion.KMIP_1_2, enums.KMIPVersion.KMIP_1_4, enums.KMIPVersion.KMIP_2_0):
        print(f"== {v.name}")
        before = failures
        run(host, port, certs, v, run_id)
        print(f"   {failures - before} failures")
    print(f"{checks} checks, {failures} failures")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
