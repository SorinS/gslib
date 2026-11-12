# pkcs11

PKCS#11 (Cryptoki) for Goose, modelled on Go's
[miekg/pkcs11](https://github.com/miekg/pkcs11): a module (an HSM's, a
smart card's, SoftHSM's shared library) loaded at run time, and every
function of its function list.

| Module | Namespace | What |
|---|---|---|
| `pkcs11` | `pkcs11::` | loading a module; every `C_*` function of PKCS#11 2.40 (the 68 of `CK_FUNCTION_LIST`); templates, mechanisms and their parameters; attribute values; EC helpers; error names |
| `pkcs11.constants` | `pkcs11::` | the 939 constants of the OASIS 3.1 header (`CKA_`, `CKM_`, `CKR_`, `CKO_`, `CKK_`, `CKF_`, ...), and name tables, made by `scripts/gen_const.py` |
| `pkcs11.p11` | `p11::` | the layer over it that miekg's `p11` is: Module, Slot, Session, Object, PrivateKey, PublicKey, SecretKey, KeyPair |

```goose
import gslib from "SorinS/gslib@v0.1";
import gslib.pkcs11;
import gslib.pkcs11.p11;

fn main() {
    var m, rv = p11::open_module("/usr/lib/softhsm/libsofthsm2.so");
    let slots, rv2 = p11::slots(m);
    var s, rv3 = p11::open_write_session(slots[0]);
    p11::login(s, "1234");

    var pubt: u8[>..] = [];
    pkcs11::attr(pubt, pkcs11::CKA_EC_PARAMS, pkcs11::EC_PARAMS_P256);
    pkcs11::attr(pubt, pkcs11::CKA_VERIFY, true);
    var privt: u8[>..] = [];
    pkcs11::attr(privt, pkcs11::CKA_SIGN, true);
    pkcs11::attr(privt, pkcs11::CKA_LABEL, "signing key");
    let kp, rk = p11::generate_key_pair(s, pkcs11::mechanism(pkcs11::CKM_EC_KEY_PAIR_GEN), pubt, privt);

    let sig, rs = p11::sign(kp.private, pkcs11::mechanism(pkcs11::CKM_ECDSA_SHA256), "message");
    if p11::verify(kp.public, pkcs11::mechanism(pkcs11::CKM_ECDSA_SHA256), "message", sig) == pkcs11::CKR_OK {
        print("verified");
    }
    p11::destroy(m);
}
```

## API

Every call returns the module's `CK_RV` as a `u64`, after its results
(`CKR_OK`, 0, for success); `pkcs11::error_text(rv)` gives
`pkcs11: 0xA0: CKR_PIN_INCORRECT`, as miekg's `Error` does. Handles
(slots, sessions, objects) are `u64`s.

### pkcs11: miekg's `Ctx`

| miekg | here |
|---|---|
| `New(path)` / `Destroy()` | `new(path) -> Ctx, bool` (and `new(path, err&)` with the loader's message) / `destroy(c&)` |
| `Initialize(...)` / `Finalize()` | `initialize(c, flags = 0)` / `finalize(c)` |
| `GetInfo`, `GetSlotList`, `GetSlotInfo`, `GetTokenInfo` | `get_info(c)`, `get_slot_list(c, present)`, `get_slot_info(c, slot)`, `get_token_info(c, slot)` (`Info`, `SlotInfo`, `TokenInfo`, blank padding trimmed) |
| `GetMechanismList`, `GetMechanismInfo` | `get_mechanism_list(c, slot) -> u64[>..]`, `get_mechanism_info(c, slot, mech)` |
| `InitToken`, `InitPIN`, `SetPIN` | `init_token(c, slot, so_pin, label)`, `init_pin(c, sh, pin)`, `set_pin(c, sh, old, new)` |
| `OpenSession`, `CloseSession`, `CloseAllSessions`, `GetSessionInfo` | `open_session(c, slot, flags) -> sh`, `close_session`, `close_all_sessions`, `get_session_info` |
| `GetOperationState`, `SetOperationState` | `get_operation_state`, `set_operation_state` |
| `Login`, `Logout` | `login(c, sh, user_type, pin)`, `logout(c, sh)` |
| `CreateObject`, `CopyObject`, `DestroyObject`, `GetObjectSize` | `create_object(c, sh, template) -> obj`, `copy_object`, `destroy_object`, `get_object_size` |
| `GetAttributeValue`, `SetAttributeValue` | `get_attribute_value(c, sh, obj, types) -> attrs`, `set_attribute_value(c, sh, obj, template)` |
| `FindObjectsInit`, `FindObjects`, `FindObjectsFinal` | `find_objects_init(c, sh, template)`, `find_objects(c, sh, max) -> u64[>..]`, `find_objects_final` |
| `EncryptInit`, `Encrypt`, `EncryptUpdate`, `EncryptFinal`, and the same for Decrypt, Digest (with `DigestKey`), Sign, SignRecover, Verify, VerifyRecover | `encrypt_init(c, sh, mech, key)`, `encrypt(c, sh, data) -> out`, `encrypt_update`, `encrypt_final`, and so on |
| `DigestEncryptUpdate`, `DecryptDigestUpdate`, `SignEncryptUpdate`, `DecryptVerifyUpdate` | the same names |
| `GenerateKey`, `GenerateKeyPair`, `WrapKey`, `UnwrapKey`, `DeriveKey` | `generate_key(c, sh, mech, template)`, `generate_key_pair(c, sh, mech, public, private) -> pub, priv, rv`, `wrap_key`, `unwrap_key`, `derive_key` |
| `SeedRandom`, `GenerateRandom` | `seed_random`, `generate_random(c, sh, n)` |
| `WaitForSlotEvent(flags) chan` | `wait_for_slot_event(c, flags) -> slot, rv`: it blocks unless `CKF_DONT_BLOCK`; Goose has no goroutine to hide that in |
| `NewAttribute(type, value)` | `attr(t&, type, value)`: overloads for `bool` (CK_BBOOL), integers (CK_ULONG), bytes and strings; `attr_date`, `attr_empty` |
| reading attributes | `attr_value(attrs, type) -> bytes, bool`, `each_attr`, `as_ulong`, `as_bool` |
| `NewMechanism(m, param)` | `mechanism(m)`, `mechanism(m, bytes)`, `mechanism_ulong` |
| `NewGCMParams`, `NewOAEPParams`, `NewPSSParams`, `NewECDH1DeriveParams`, `RSAAESKeyWrapParams` | `mechanism_gcm`, `mechanism_oaep`, `mechanism_pss`, `mechanism_ecdh1`, `mechanism_rsa_aes_kw`; and `mechanism_ccm`, `mechanism_eddsa` (PKCS#11 3.0's `CK_EDDSA_PARAMS`) |

EC helpers: `EC_PARAMS_P256`, `_P384`, `_P521`, `_ED25519`, `_X25519` (the
DER OIDs `CKA_EC_PARAMS` takes); `ec_point(v)` (the point out of
`CKA_EC_POINT`'s OCTET STRING), `ec_point_der(point)`.

### p11: miekg's p11

`open_module(path)` (loads and initializes it, a module already
initialized taken as it is), `info`, `slots`, `destroy`; a `Slot`'s
`info`, `token_info`, `open_session`, `open_write_session`,
`open_session_with_flags`, `close_all_sessions`, `mechanisms`,
`mechanism_info`, `init_token`; a `Session`'s `login`,
`login_security_officer`, `login_as`, `logout`, `init_pin`, `set_pin`,
`close`, `generate_random`, `create_object`, `find_objects`,
`find_object` (`ERR_NO_OBJECT`, `ERR_MULTIPLE_OBJECTS`),
`find_private_key`, `find_public_key`, `find_secret_key` (by label),
`generate_key_pair`, `generate_key`; an `Object`'s `attribute`, `label`,
`value`, `set`, `copy_object`, `destroy`; `sign`, `decrypt`, `derive`,
`derive_value` of a `PrivateKey`, `verify` and `encrypt` of a
`PublicKey`, `encrypt` and `decrypt` of a `SecretKey`.

## How it works

`pkcs11/src/p11.c`, in the package's sidecar, loads the module (`dlopen`,
or `LoadLibrary` on Windows), takes its `CK_FUNCTION_LIST` from
`C_GetFunctionList` and calls through it. It declares the PKCS#11 types it
uses itself, rather than including the OASIS headers: `CK_ULONG` as the
platform's `unsigned long` (4 bytes on Windows), structures packed to 1
byte on Windows as Cryptoki there wants them. The order of the 68 functions
and the layout of every structure were checked against the OASIS 3.1
headers. Goose and C pass byte encodings; integers in them are 64-bit
little-endian:

| Encoding | Layout |
|---|---|
| a template | repeated: `u64 type`, `u64 len`, `len` bytes |
| a mechanism | `u64 type`, `u64 kind`, the kind's fields: `NONE`; `RAW`: bytes; `GCM`: iv, aad, `u64` tag bits; `OAEP`: `u64` hash, mgf, source, data; `PSS`: `u64` hash, mgf, salt length; `ECDH1`: `u64` kdf, shared data, public data; `RSA_AES_KW`: `u64` AES bits, then OAEP's; `EDDSA`: `u64` prehash, context; `ULONG`: `u64`; `CCM`: `u64` data length, nonce, aad, `u64` MAC length (bytes are `u64 len` + bytes) |
| attribute types asked for | repeated `u64` |
| attributes given back | repeated: `u64 type`, `u64 len` (all ones, with no bytes, for one the module did not give), `len` bytes |
| info structures | their fields in order: `u64`s, then versions (2 bytes each), then the blank-padded strings at their fixed lengths |

Results of unknown size use PKCS#11's two calls (the length, then the
data), retried if the module's answer grows in between.

## Tests

`python3 scripts/run_tests.py` (or `make test-pkcs11`) runs every
test/*.goose at -O0, -O2 and `--debug` (and natively with `--native`),
each on a fresh SoftHSM2 token made by `softhsm2-util`; without SoftHSM2
the tests are skipped. Each cryptographic result is checked with
crypto/bignum, an implementation of its own:

| Test | What |
|---|---|
| module | loading, and refusing what is no module; info, slots, tokens, mechanisms; sessions and their states; login, a wrong PIN, changing the PIN; a second token initialized and its PIN set by the SO; random bytes; error names; p11's module, slots and sessions |
| objects | data objects created, found (by label, by class, in batches), read (several attributes, one the object lacks), changed, copied, sized, destroyed; a sensitive key's other attributes read past `CKR_ATTRIBUTE_SENSITIVE`; p11's finds and their errors |
| operations | every operation path dispatched at least once: signing and verifying in parts (equal to the one-part HMAC, a changed byte refused), decrypting in parts, the CK_ULONG, CCM and EdDSA parameters; recovery, the dual-function updates, operation state, slot events and the legacy calls reach the module (SoftHSM answers most with `CKR_FUNCTION_NOT_SUPPORTED`) |
| crypto | AES-CBC-PAD (one part and several), ECB, GCM, AES Key Wrap, SHA-256, SHA-512, HMAC, each equal to bignum's; RSA keys made on the token, PKCS #1 v1.5 and PSS signatures verified by bignum, OAEP from bignum decrypted; ECDSA on P-256 and P-384 both ways; Ed25519 verified by bignum; ECDH with a bignum key, the derived key equal to bignum's; p11's keys |

`python3 scripts/interop.py` (`make interop-pkcs11`, needs SoftHSM2,
OpenSC's `pkcs11-tool` and OpenSSL): Goose makes RSA, P-256, Ed25519 and
AES keys, which pkcs11-tool lists; pkcs11-tool verifies Goose's RSA PKCS
#1 v1.5, RSA-PSS, ECDSA (raw and with SHA-256) and EdDSA signatures; OpenSSL
verifies Goose's RSA signature with the public key pkcs11-tool reads out of
the token; pkcs11-tool makes keys of each kind and signs, and Goose
verifies. 33 checks. pkcs11-tool is given keys by ID and type, not label: a
pair's halves share a label, SoftHSM lists objects in no fixed order, and
pkcs11-tool given a label takes whichever half comes first.

Tested on macOS (arm64) with SoftHSM 2.7.0 and OpenSC 0.27.1. The Linux
and Windows paths (`dlopen` with `-ldl`; `LoadLibrary`, 4-byte `CK_ULONG`,
1-byte packing) are written but not yet run.

## Limits

- **Mechanism parameters live for the call.** A mechanism's parameter is
  built for the `*_init` (or key) call and freed after it, as miekg frees
  all but GCM's. Modules copy it at Init, as SoftHSM does; a module that
  writes the GCM IV back into the parameter later (miekg's comment names
  CloudHSM) is not supported.
- **SoftHSM's RSA-OAEP is SHA-1 only**: other hashes are
  `CKR_ARGUMENTS_BAD`, a limit of SoftHSM, not of this package.
- **PKCS#11 2.40's function list.** The 3.0 interfaces (`C_GetInterface`,
  message-based encryption, `C_LoginUser`, `C_SessionCancel`) are not
  called, as miekg does not; 3.0's mechanisms and constants (EdDSA, ...)
  work through the 2.40 functions, as they do here.
- `C_Initialize` takes flags only (`CKF_OS_LOCKING_OK` and the like): no
  mutex callbacks.
