// encoded_words: puts non-ASCII text in mail headers as RFC 2047
// encoded-words (=?UTF-8?q?...?= and =?UTF-8?b?...?=) and reads them back
// out of a header, including one in a charset the program converts itself.
//
//   goose examples/mime/encoded_words.goose

import std;
import os;
import gslib from "../..";
import gslib.mime;
import gslib.mime.encodedword;

fn main() {
    // Q encoding keeps mostly-ASCII text readable; B (base64) is shorter
    // for text that is mostly not ASCII. Plain ASCII is left as it is.
    let subject = "Café meeting: ¡ready?";
    let q = mime::encode_word(mime::Q_ENCODING, "UTF-8", subject);
    let b = mime::encode_word(mime::B_ENCODING, "UTF-8", "日本語のメール");
    let plain = mime::encode_word(mime::Q_ENCODING, "UTF-8", "Hello");
    print("Subject: ", q);
    print("Subject: ", b);
    print("Subject: ", plain);
    guard starts_with(q, "=?UTF-8?q?") && starts_with(b, "=?UTF-8?b?") && plain == "Hello" else {
        print("encoded_words: wrong encoding");
        exit(1);
    }

    // One word back.
    var out: u8[>..] = [];
    var e = mime::decode_word(out, q);
    guard e == mime::OK && out[..] == subject else { print("encoded_words: decode_word: ", mime::error_text(e)); exit(1); }

    // A whole header: text around the words stays. ISO-8859-1 and
    // US-ASCII are built in besides UTF-8.
    let from = "=?ISO-8859-1?Q?Andr=E9_Martin?= <andre@example.com>";
    out.clear();
    e = mime::decode_header(out, from);
    print("From: ", out);
    guard e == mime::OK && out[..] == "André Martin <andre@example.com>" else { print("encoded_words: decode_header"); exit(1); }

    // A long subject folded into several words: words next to each other
    // join, and the white space between them goes.
    let folded = "=?UTF-8?q?Caf=C3=A9_?=\r\n =?UTF-8?b?bWVldGluZw==?= today";
    out.clear();
    e = mime::decode_header(out, folded);
    print("Subject: ", out);
    guard e == mime::OK && out[..] == "Café meeting today" else { print("encoded_words: folded words"); exit(1); }

    // Other charsets: the block gets the charset (lower case) and the
    // decoded bytes, and appends UTF-8. Here ISO-8859-15, where 0xA4 is €.
    let price = "Price: =?ISO-8859-15?q?10_=A4?=";
    out.clear();
    // The block's value is its result: mime::OK or an error code.
    e = mime::decode_header_charset(out, price) { cs: const u8[:], content: const u8[:], dst: u8[>..]& =>
        let known = cs == "iso-8859-15";
        if known {
            for c in content {
                if c == 0xa4 { dst.append("€"); }
                else if c < 0x80 { dst.push(c); }
                else { dst.push((0xc0 | (c >> 6)) as! u8); dst.push((0x80 | (c & 0x3f)) as! u8); }
            }
        }
        if known { mime::OK } else { mime::ERR_UNHANDLED_CHARSET }
    };
    print(out);
    guard e == mime::OK && out[..] == "Price: 10 €" else { print("encoded_words: decode_header_charset: ", mime::error_text(e)); exit(1); }

    // Without such a block an unknown charset is an error, and the word
    // is left as it was; a malformed word is plain text.
    out.clear();
    e = mime::decode_header(out, price);
    var msg: u8[>..] = [];
    mime::header_error(msg, price);
    print(msg);
    guard e == mime::ERR_UNHANDLED_CHARSET else { print("encoded_words: an unknown charset was taken"); exit(1); }
    out.clear();
    e = mime::decode_header(out, "=?UTF-8?x?abc?= stays");
    guard e == mime::OK && out[..] == "=?UTF-8?x?abc?= stays" else { print("encoded_words: a bad word was decoded"); exit(1); }
}
