// Fuzz target: mail_msg. An incoming message as mail/ reads one, selected by
// the first byte:
//   0: the MIME walk: CRLF-normalized, header split (split_entity,
//      next_field, field_name, field_value, header_get), RFC 2047 subject,
//      From's addr-spec (from_address), Content-Type (boundary, protocol),
//      multipart bodies split into parts (pgp's parts_of, smime's
//      split_signed) and walked with a work list, each part's body decoded
//      by its Content-Transfer-Encoding (base64, quoted-printable).
//   1: addresses: parse_address and parse_address_list, written back
//      (write_address, address_string, write_display_name), and a Msg
//      built from the parsed values (From, To, Cc, Reply-To, Subject, a
//      header) and written, with a fixed date, Message-ID and boundary.
//   2: PGP/MIME (pgp::open and verify, against RFC 3156 test keys) and
//      S/MIME (smime::verify): every layer opened as far as it goes.

import std;
import gslib from "../..";
import gslib.mime;
import gslib.mime.encodedword;
import gslib.mime.quotedprintable;
import gslib.crypto.openpgp;
import gslib.crypto.openpgp.keyring;
import gslib.mail;
import gslib.mail.address;
import gslib.mail.message;
import gslib.mail.pgp;
import gslib.mail.smime;

let MAX_PARTS: i64 = 64;
let MAX_DEPTH: i64 = 8;

// mail/test/pgp/keys.pub (RFC 3156 test keys, Alice and Bob), in hex.
let KEYS_PUB_HEX = str(
    "9833046af7d74216092b06010401da470f01010740a796d394d49bc74b90f079c13d24c9e1fa41590bc376ecaa6661e8",
    "69c76dafb2b419416c696365203c616c696365406578616d706c652e636f6d3e88af0413160a00571621040bf1a5b127",
    "a77553d569d385ccad86a79694691205026af7d7421b14800000000004000e6d616e75322c322e352b312e31322c302c",
    "33021b03050b0908070202220206150a09080b020416020301021e07021780000a0910ccad86a7969469121e0c00fe2f",
    "307af999cc3fae47dedc8df01241e157970ac55bb43bf25075d8f37965f65e00ff6c552b9d7693c797cb16acb6d2dc90",
    "4e04ac33ca98303ca3033c27ed8bdbb906b838046af7d742120a2b06010401975501050101074071d83e0a6490d1805b",
    "af7c6d0fe24bc14f235628b2a0dc130bc8b0e61592634d0301080788940418160a003c1621040bf1a5b127a77553d569",
    "d385ccad86a79694691205026af7d7421b14800000000004000e6d616e75322c322e352b312e31322c302c33021b0c00",
    "0a0910ccad86a7969469122c1a0100ff357eebf2026e0f5de9426572aeaaa2247458b852834f1164746e02fad178f300",
    "fd1ee18f17b98cee5c563436b2681b18bab84a44d04a7067c2e919241586e8800599018d046af7d743010c009d386962",
    "20e9087ae5b1a766103161d23da6a241a0e3ffa9266fdafce8ca60fb97309c928627a9d91a8c7483052c894651b579f7",
    "a15c6c240605cca6dce252823a04348a258b57eb8ccaa4eea828b055c35d646706254716280ef535271efda3e781d89a",
    "fbe84fcbc017fde446742ce2e2342e79d89bb9c6a0cad74cca7caa3a9bfc44c33919ec2b91983036b96e1e5713a03571",
    "879199205291c8075fc4295390781a352295e4704df9db59d03625e5d55d697163d28a28d193e11624d11168ffbe84a4",
    "5c3c4b8deaf5129c5241b4d1af9b423058cba31aadaa04e23ae02d573b93d69bf8177a5fba89a444e180cada77d2a92c",
    "b47ef54bd6e9c6629fd12abc6a84051ec0361bfb0f38f064ef3488d456db4e4659359f77bc13b00323a31e04f86d5a64",
    "9cc17fd2dba584339270fade8d120299a0d86868be6ebb272b8f12dd5608463b69d059ee5f94feec988ab08a97f8cf95",
    "4f9135abb3e06540f12adb36b14f3f857e3d9ebf55875673cd8e8594277164e3d7648ab9b28abe33c0aa6c3f00110100",
    "01b415426f62203c626f62406578616d706c652e636f6d3e8901ee041301080058162104c97e758fb92ab239cd82e91c",
    "71f33c3dc954e33405026af7d7431b14800000000004000e6d616e75322c322e352b312e31322c302c33031b2f04050b",
    "0908070202220206150a09080b020416020301021e07021780000a091071f33c3dc954e3343e8b0bfe3b7d301c51c5f0",
    "1eefbb017fc7c86889fc51963afd37a7ff2f2fd134ce58d24d05da94a2e466d93f76a38734ccfd81e3f6834649b35518",
    "342189f5b40ce572eb2b68d004431ceea131ec1fb43828cbd97b66bb25954cc25a5fd6da2076c7505047606fb0a48c17",
    "ccfa7a24932322391ce9222b720259ab37a0e2c10f44e66ff94959aa4b6d8c33a8f5bf0d4cf1f7339787ca9b5992431c",
    "f7687a5785f65527c1b4df978bafedefcb37be165965827d9b1ad1bb49201c41ba93e961ba08e080571c95d82e20f2b1",
    "ad3d708f03e939fa062392bccd9bd72bdfcb79021dcb74ee91a552bbc5242c0c354fc94839bfe8893f1b6ceb54eb0d20",
    "810e021badc11b0a603dbd34a01b2365e4576db3e131893dbb240b505c82cd21265bd1ab14e0d614eb87276354650cac",
    "4702dbe8e061415c81ede0e97db2c4de7e469d6b1454b48cb9853d0d301aa93c6b47db33610f25f2ade382d816cbd8cb",
    "15d0ab236ed7a8cc0357ba369196a0b96d0d4c9b16f073f850f14aa1ceca9d91f13f8c15147d9debcab9018d046af7d7",
    "43010c00b3793c204e92a36f1cf33ee229819c9ecbd580567dc036fd57dfb4150c040abc3aae116d406409947bd25216",
    "17413fb5b5e035e823d0b08d91b2a615f30e9ffe91e591fefcdc40983dcb1d5938dfc9718f3e4610d1fadd7e2246045c",
    "19ebedcb38092bd63b128b9e5b6de95790115359e907a20f8668f5171cf1ec0aa86f9c2b606f601dcb5c118535216e70",
    "0f424e7a4219692b0876c193170ead820c452295e8c726d56c3ce692e11ee0cd9c8ed313d9b44d4598b2574957fe7d65",
    "1f0be247c515b4f896ef9e1a42e8662bec10921445f79bfada6b88aef67d0109287d921271a5700496843625a64192ad",
    "5ea2674343a78a5b05f9cd1fda9da9a8f69d5eea7c06a041257769e100ba1c07f7eccef2568da2f3fe88ae6601e4569d",
    "229755ca26d7318644973e58f158f511ed726cbe4043180323f6c36b1c76ade3bb6c90468ef87143aeab974eff7d2dd2",
    "cc362851465d221a8a1a2a88110bde97912138fa12dd94c9520ff82c415d6225964a104c42029b0470cade7ce84856ef",
    "071744c7001101000189038804180108003c162104c97e758fb92ab239cd82e91c71f33c3dc954e33405026af7d7431b",
    "14800000000004000e6d616e75322c322e352b312e31322c302c33021b2e01c0091071f33c3dc954e334c0f420041901",
    "08001d1621041a0297ebd9bdae305e9799754b06f1311354c80305026af7d743000a09104b06f1311354c80308d80bfe",
    "2572a902da70a6e967bffd24589e19c50078ff4589c068f30d629cf81ba6fd5cb3441334095915645fad0e61246c36d8",
    "da5818f72aea7201ea831a4708ec0eb9bd5266070d0d11e9e5db0283a70e6eaec4a1aa8ff6ee673c0f2648fc0db32409",
    "ea3a1bed8a8e6cb999441dfe8ad5a4d79279d77a910bae372cb95f69880220eccea2433ad393b63d8d25aedb75fe7718",
    "9c072f7de9d5f01778fb7bd5909d70a54ce05a3c92bdb4eb9d050b398d4cc3027858077621de1957d966230510bb2216",
    "e278fd80a9483a115b178090f7a368c2441e1c20b1126ea71a1472e15b1ad6fde65c4ce9f1c4973e003d3b08604b7eaf",
    "cec7a8b2806aafd03f856d1eb709e4b27c77296a17a246b4c2eccff77d955c8b70cfebf2d5d1b09a634d078f5b433b6f",
    "02139f42caa8676c778e5e7008334bf6a50bb8821d977ba6e4a099f6fa6e51516d44b6ebcc8ca7d02cbe6245cb9d0365",
    "d1a6abd37d1c06351e606e53519cd23f1e7dc1d07679da678ee37b9eacd12746510e427b9a3e3a39837bc4273d189df8",
    "d3350c008c673bac97e863d84a8e88803b365a7441153b6cc7a3905b0f6dc7e4dd2e94081eb95ccf3b8c67a3fadf4934",
    "be2cad94060ab9284c99fc55d5bd9248ebe9f53a87172e6dd34a97a7b8fc70ca2ceb5fccb19d64b307e393193770d6df",
    "e41c3ce574cfc4a9431adaeae91314dd4c5b5d3525b861236bc2b48b7121050fe6583439310c850c87b5a62b4d34299e",
    "61b273838de708e6175da96361b3d45467df2781443f7f7300c129a6ed6b66977148fae6c2f5597b1ce8a3ce433e47a7",
    "d50a746651999f386ccb17292b689108587433708fe1d459d9653f42ea116dd6fb150a75ac1e17f0e8d99e38c1367025",
    "acd80c6ad48d6d64ed2ba816f5871f6c63e64dccdbcf00150aada035a9e2c3396a0a5b84c7f4b64c7df37d95bf8af872",
    "ed1f63558bcac2d6d0123b784a3823b5f2aab371567790fd59a5765fcf7a52c23a7ab91e89d81eb7c50f5a508163055f",
    "8437138a050961b9ffa1d52d4f6812df5c5b7a56b18b6f5a9d5afab77a1893afb8a19f9e8827e3311ac57fef3388fc7e",
    "82471a89",
);

var KR = openpgp::Keyring { .. };

fn decode_part(h: const u8[:], body: const u8[:]) {
    let _ = smime::decode_body(h, body);
    let cte, has = smime::header_get(h, "Content-Transfer-Encoding");
    if has && mail::eq_fold(cte, "quoted-printable") {
        var qr = quotedprintable::new_reader();
        var out: u8[>..] = [];
        let _ = quotedprintable::decode(qr, out, body);
        let _ = quotedprintable::finish(qr, out);
    }
    var at = 0;
    var n = 0;
    while at < h.len && n < 256 {
        let e = smime::next_field(h, at);
        let f = h[at..e];
        let _ = smime::field_name(f);
        let _ = smime::field_value(f);
        if e <= at { break; }
        at = e;
        n++;
    }
}

struct Ent { pos: i64, end: i64, depth: i64 }

fn walk(m: const u8[:]) {
    var todo: Ent[>..] = [Ent { pos: 0, end: m.len, depth: 0 }];
    var seen = 0;
    while todo.len > 0 && seen < MAX_PARTS {
        let x = todo[todo.len - 1];
        todo.resize(todo.len - 1);
        seen++;
        let ent = m[x.pos..x.end];
        let he, bs = smime::split_entity(ent);
        let h = ent[..he];
        let body = ent[bs..];
        decode_part(h, body);
        let t, b, p = pgp::content_type(h);
        if b.len == 0 || x.depth >= MAX_DEPTH { continue; }
        let _ = smime::split_signed(body, b);
        var spans: i64[>..] = [];
        if pgp::parts_of(body, b, spans) {
            var i = 0;
            while i + 1 < spans.len {
                todo.push(Ent { pos: x.pos + bs + spans[i], end: x.pos + bs + spans[i + 1], depth: x.depth + 1 });
                i += 2;
            }
        }
    }
}

fn message(data: const u8[:]) {
    var m: u8[>..] = [];
    smime::crlf(m, data);
    let he, bs = smime::split_entity(m);
    let h = m[..he];
    let subj, hs = smime::header_get(h, "Subject");
    if hs {
        var d: u8[>..] = [];
        let _ = mime::decode_header(d, subj);
    }
    for name in ["From", "To", "Cc", "Reply-To", "Sender"] {
        let v, ok = smime::header_get(h, name);
        if ok {
            var l: mail::Address[>..] = [];
            let _ = mail::parse_address_list(v, l);
        }
    }
    let _ = smime::from_address(data);
    var outer: u8[>..] = [];
    var inner: u8[>..] = [];
    smime::split_message(m, outer, inner);
    walk(m);
}

fn addresses(data: const u8[:]) {
    var out: u8[>..] = [];
    let a, e = mail::parse_address(data);
    if e == mail::OK {
        mail::write_address(out, a);
        let _ = mail::address_string(a);
        mail::write_display_name(out, a.name);
        let _ = mail::make_address(a.name, a.addr);
    }
    var l: mail::Address[>..] = [];
    let el = mail::parse_address_list(data, l);
    for &x in l { mail::write_address(out, x); }

    var msg = mail::Msg { .. };
    mail::set_date(msg, 1700000000);
    // Fixed, so that write never draws random bytes.
    if mail::set_message_id(msg, "fuzz@example.com") != mail::OK || mail::set_boundary(msg, "fuzzboundary") != mail::OK {
        abort("fuzz: msg defaults");
    }
    if e == mail::OK { mail::set_from(msg, a); } else { let _ = mail::set_from(msg, "a@example.com"); }
    for &x in l { mail::add_to(msg, x); }
    let _ = mail::add_cc(msg, data);
    let _ = mail::set_reply_to(msg, data);
    let _ = mail::set_subject(msg, data);
    let _ = mail::add_header(msg, "X-Fuzz", data);
    let _ = mail::set_body(msg, mail::TEXT_PLAIN, data);
    var w: u8[>..] = [];
    let _ = mail::write(msg, w);
    var rc: u8[][>..] = [];
    mail::recipients(msg, rc);
    let _ = mail::envelope_from(msg);
    let _ = mail::needs_smtputf8(msg);
}

fn secure(data: const u8[:]) {
    var r = pgp::Opened { .. };
    let _ = pgp::open(data, KR, "", r);
    var r2 = pgp::Opened { .. };
    let _ = pgp::verify(data, KR, r2);
    var r3 = smime::Opened { .. };
    let _ = smime::verify(data, r3);
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len == 0 { return 0; }
    let rest = data[1..];
    match data[0] % 3 {
        0 => { message(rest); },
        1 => { addresses(rest); },
        _ => { secure(rest); },
    }
    return 0;
}

fn nibble(c: u8) -> u8 { if c <= '9' { c - '0' } else { c - 'a' + 10 } }

fn main() {
    var keys: u8[>..] = [];
    var i = 0;
    while i + 1 < KEYS_PUB_HEX.len {
        keys.push(nibble(KEYS_PUB_HEX[i]) * 16 + nibble(KEYS_PUB_HEX[i + 1]));
        i += 2;
    }
    if openpgp::add_keys(KR, keys) != openpgp::OK { abort("fuzz: keys"); }
}
