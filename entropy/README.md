# entropy

Cryptographically secure random bytes from the operating system for
Goose, as Go's crypto/rand: for keys, nonces, salts, tokens and anything
else an attacker must not guess. It is a thin layer over goose's
`os::random_bytes` (goose.git from ee261a4c on), kept as a package so a
program can put another in its place.

| Platform | Source |
|---|---|
| macOS, Linux, the BSDs | `getentropy(3)`, 256 bytes per call; `/dev/urandom` if the kernel has no getentropy (Linux before 3.17) |
| Windows | `ProcessPrng` on Windows 10 and later, `RtlGenRandom` before, looked up at run time so no library is linked |

```goose
import gslib from "SorinS/gslib@v0.7.0";
import gslib.entropy;

fn main() {
    var key: u8[32] = [0; 32];
    entropy::random_bytes(key);               // stops the program if the OS gives nothing

    var salt: u8[16] = [0; 16];
    if !entropy::try_random_bytes(salt) {     // or find out, and go on without
        print("no random bytes");
    }
}
```

| Function | What |
|---|---|
| `random_bytes(out: u8[:])` | Fills `out`. If the OS gives no bytes, which a working system never does, the program stops: a key that is not random is worse than none |
| `try_random_bytes(out: u8[:]) -> bool` | Fills `out`; false if the OS gave none, and then `out` is not to be used |

std's `rng` is a fast generator for simulations and tests, and os's
`random_seed` falls back to the clocks when it has to: neither is for
secrets. Nothing is buffered, so a forked process never repeats its
parent's bytes. There is no C: goose's runtime has it.

## Replacing it

Goose has no interfaces, but a program chooses its packages. The
libraries that need randomness (bignum, and through it x509, tls, ssh,
openpgp, krb5, jwx and the rest) all take it from `entropy::random_bytes`,
and in their standalone repositories they import `entropy` by name only,
with no source. The program's root file declares where `entropy` comes
from, and any package of that name whose functions match the ones called
takes this one's place:

```goose
import tls from "SorinS/tlsgoose@v0.8.0";
import entropy from "../fixed_entropy";   // instead of "SorinS/entropygoose@v0.8.0"
```

```goose
// fixed_entropy/entropy.goose: the same bytes on every run, for tests
// that compare against recorded output. Never for anything real.
namespace entropy;

var counter: u64 = 0;

fn random_bytes(out: u8[:]) {
    for i in out.len { counter += 1; out[i] = ((counter * 0x9e3779b97f4a7c15) >> 56) as! u8; }
}

fn try_random_bytes(out: u8[:]) -> bool { random_bytes(out); return true; }
```

The same works for a TPM's or an HSM's generator (`tpm2`'s GetRandom,
`pkcs11`'s C_GenerateRandom), or a DRBG seeded from one. Inside gslib the
libraries and entropy are one package, so there it is always this one.

## Tests

```bash
python3 scripts/run_tests.py            # under the JIT at -O0, -O2 and --debug, plus examples/entropy
python3 scripts/run_tests.py --native   # also built with the C compiler
```

The test fills buffers of several sizes (more than one getentropy call,
an empty one, the middle of a larger one with its edges untouched),
checks that two draws differ and that 64 KiB has every byte value about
equally often. It passes on macOS, Linux and Windows. The example
(`examples/entropy/random.goose`) makes a key, a salt, a session token, a
version 4 UUID and unbiased dice throws.
