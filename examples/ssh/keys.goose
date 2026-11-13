// keys: SSH keys as ssh-keygen makes and reads them. A new Ed25519 key is
// written in OpenSSH's format, plain and under a passphrase, and read
// back; its authorized_keys line and fingerprints are printed. An ECDSA
// key from x509, as PEM PKCS #8, is read too. Each key signs and its
// public key verifies.
//
//   goose examples/ssh/keys.goose

import std;
import gslib from "../..";
import gslib.crypto.ssh;
import gslib.crypto.ssh.keys;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.encoding.asn1;

fn run() {
    // A new key, with a comment, as `ssh-keygen -t ed25519 -C ...`.
    var k = ssh::generate_key(x509::KEY_ED25519);
    k.comment.append("alice@example.com");

    // Its .pub file / authorized_keys line, and back.
    let line = ssh::marshal_authorized_key(k.public, k.comment);
    let pub, options, comment, ok = ssh::parse_authorized_key(line);
    guard ok && pub.blob == k.public.blob && comment == "alice@example.com" else { print("keys: the public line did not read back"); exit(1); }
    print(line[..line.len - 1]);
    print("fingerprint ", ssh::fingerprint_sha256(k.public));
    print("fingerprint MD5:", ssh::fingerprint_md5(k.public));

    // The private key file: unprotected, then under a passphrase.
    let plain = ssh::marshal_private_key(k);
    let k1, e1 = ssh::parse_private_key(plain);
    guard e1 == ssh::KEY_OK && k1.public.blob == k.public.blob && k1.comment == k.comment else { print("keys: the key file did not read back"); exit(1); }
    let protected = ssh::marshal_private_key(k, "correct horse", "aes256-ctr", 16);   // ssh-keygen's cipher and rounds
    let k2, e2 = ssh::parse_private_key(protected);
    guard e2 == ssh::KEY_ENCRYPTED else { print("keys: a protected key read without its passphrase"); exit(1); }
    let k3, e3 = ssh::parse_private_key(protected, "wrong");
    guard e3 == ssh::KEY_BAD_PASSPHRASE else { print("keys: a wrong passphrase was taken"); exit(1); }
    let k4, e4 = ssh::parse_private_key(protected, "correct horse");
    guard e4 == ssh::KEY_OK && k4.public.blob == k.public.blob else { print("keys: the passphrase did not open the key"); exit(1); }
    print("key file: ", plain.len, " bytes plain, ", protected.len, " under a passphrase (aes256-ctr, bcrypt_pbkdf)");

    // A PEM key (PKCS #8, as openssl writes it), made here with x509.
    let xk = x509::generate_key(x509::KEY_EC_P256);
    var pem: u8[>..] = [];
    asn1::pem_encode(pem, "PRIVATE KEY", x509::marshal_pkcs8(xk));
    let ek, e5 = ssh::parse_private_key(pem);
    guard e5 == ssh::KEY_OK && ek.public.kind == x509::KEY_EC_P256 else { print("keys: the PEM key did not read"); exit(1); }
    print("PEM key: ", ssh::key_type(ek.key.kind), " ", ssh::fingerprint_sha256(ek.public));

    // Signatures, as authentication makes them.
    let data = "data to sign";
    let s1, oks1 = ssh::sign(k4, ssh::SIG_ED25519, data);
    let s2, oks2 = ssh::sign(ek, ssh::SIG_ECDSA_P256, data);
    guard oks1 && oks2 && ssh::verify(k.public, ssh::SIG_ED25519, data, s1) && ssh::verify(ek.public, ssh::SIG_ECDSA_P256, data, s2)
    else { print("keys: a signature did not verify"); exit(1); }
    guard !ssh::verify(k.public, ssh::SIG_ED25519, "other data", s1) else { print("keys: a signature verified for other data"); exit(1); }
    print("signatures: ssh-ed25519 and ecdsa-sha2-nistp256 verify");
}

fn main() {
    run();
}
