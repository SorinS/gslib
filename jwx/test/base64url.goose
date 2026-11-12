// jwx's base64url (RFC 4648 §5 without padding, RFC 7515 §2) and jwa's
// names: RFC 4648 §10's vectors in the URL alphabet, every byte value and
// length up to 64 round-tripped, and the encodings a strict decoder must
// refuse; every algorithm, key type and curve name looked up and back.
import std;
import gslib from "../..";
import gslib.jwx;
import gslib.jwx.jwa;
import tv;

fn main() {
    let cases = [["", ""], ["f", "Zg"], ["fo", "Zm8"], ["foo", "Zm9v"], ["foob", "Zm9vYg"],
                 ["fooba", "Zm9vYmE"], ["foobar", "Zm9vYmFy"]];
    for c in cases {
        tv::check_eq(str("encode ", c[0]), jwx::b64_encode(c[0]), c[1]);
        let d, ok = jwx::b64_decode(c[1]);
        tv::check(str("decode ", c[1]), ok && d == c[0]);
    }
    // The two URL-alphabet characters: 0xfb 0xff = "-_8".
    var b: u8[>..] = [];
    b.push(0xfb); b.push(0xff);
    tv::check_eq("url alphabet", jwx::b64_encode(b), "-_8");
    // RFC 7515 §2's example: the octets 3, 236, 255, 224, 193.
    var e: u8[>..] = [];
    for x in [3, 236, 255, 224, 193] { e.push(x as! u8); }
    tv::check_eq("RFC 7515 example", jwx::b64_encode(e), "A-z_4ME");

    for n in 65 {
        var data: u8[>..] = [];
        for i in n { data.push((i * 37 + n * 11) as! u8); }
        let enc = jwx::b64_encode(data);
        let dec, ok = jwx::b64_decode(enc);
        tv::check(str("round trip ", n), ok && dec == data);
    }
    var all: u8[>..] = [];
    for i in 256 { all.push(i as! u8); }
    let dec, ok = jwx::b64_decode(jwx::b64_encode(all));
    tv::check("every byte", ok && dec == all);

    // Padding, the standard alphabet, white space, an odd length, and
    // non-zero trailing bits ("Zh" and "Zm9" are "f" and "fo" with stray bits).
    for bad in ["Zg==", "Zm9v+", "Zm9v/", "Zm 9v", "Z", "Zm9vY", "Zh", "Zm9", "Zm8=", "\n"] {
        let x, okb = jwx::b64_decode(bad);
        tv::check(str("refused ", bad), !okb && x.len == 0);
    }

    for a in jwa::ALL {
        tv::check_int(str("lookup ", jwa::name(a)), jwa::lookup(jwa::name(a)), a);
    }
    tv::check_int("names are case-sensitive", jwa::lookup("hs256"), jwa::UNKNOWN);
    tv::check_int("dir", jwa::lookup("dir"), jwa::DIRECT);
    for k in [jwa::KTY_EC, jwa::KTY_RSA, jwa::KTY_OKP, jwa::KTY_OCT] {
        tv::check_int(str("kty ", jwa::kty_name(k)), jwa::kty_lookup(jwa::kty_name(k)), k);
    }
    for c in [jwa::CRV_P256, jwa::CRV_P384, jwa::CRV_P521, jwa::CRV_ED25519, jwa::CRV_X25519] {
        tv::check_int(str("crv ", jwa::crv_name(c)), jwa::crv_lookup(jwa::crv_name(c)), c);
    }
    tv::done("base64url");
}
