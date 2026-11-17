// entropy: cryptographically secure random bytes from the operating
// system, for keys, nonces, salts and tokens, after Go's crypto/rand.
// getentropy(3) on macOS, Linux and the BSDs (/dev/urandom where the
// kernel lacks it), BCryptGenRandom on Windows. The C is
// entropy/src/entropy.c, compiled only into programs that call it.
// std's rng is a fast generator for simulations and tests, and os's
// random_seed falls back to the clocks: neither is for secrets.
//
//   import gslib.entropy;        // from a program; `import entropy;` inside gslib
//
//   var key: u8[32] = [0; 32];
//   entropy::random_bytes(key);              // stops the program if the OS gives nothing
//   if !entropy::try_random_bytes(nonce) { ... }
//
// The libraries that need randomness (bignum, and through it tls, x509,
// ssh, krb5, ...) all take it from here, and their standalone packages
// import entropy by name only, without a source. A program therefore
// chooses the package it declares as entropy, and any package of that
// name whose functions match the ones called (usually random_bytes) takes
// this one's place: a fixed generator for reproducible tests, or a TPM or
// an HSM.

namespace entropy;

extern fn gsent_fill(out: u8[:]) -> i64;

// Fills out with random bytes from the OS. If the OS cannot give them,
// which does not happen on a working system, the program stops: going on
// with a key that is not random is worse.
fn random_bytes(out: u8[:]) {
    assert(gsent_fill(out) == 0);
}

// Fills out with random bytes from the OS: true, or false if the OS gave
// none, and then out is not to be used.
fn try_random_bytes(out: u8[:]) -> bool {
    return gsent_fill(out) == 0;
}
