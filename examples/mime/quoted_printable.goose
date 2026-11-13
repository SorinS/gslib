// quoted_printable: encodes a mail body as quoted-printable (lines of at
// most 76 bytes, non-ASCII as =XX) and decodes it back, whole and as it
// arrives in pieces; then the Binary mode, and a body that is not valid.
//
//   goose examples/mime/quoted_printable.goose

import std;
import os;
import gslib from "../..";
import gslib.mime;
import gslib.mime.quotedprintable;

fn main() {
    var body: u8[>..] = [];
    body.append("Grüße aus München! Price: 5 € = about 5.40 $.\r\n");
    body.append("This line is long enough that the encoder has to break it with a soft line break, an = at its end.\r\n");
    body.append("Trailing spaces are kept:   \r\n");

    // Whole buffers. Line ends in the text stay line ends.
    var qp: u8[>..] = [];
    quotedprintable::encode_all(qp, body);
    print(qp);
    each_split(qp, '\n') {
        guard it.len <= 77 else { print("quoted_printable: a line of ", it.len, " bytes"); exit(1); }
    };
    var back: u8[>..] = [];
    var e = quotedprintable::decode_all(back, qp);
    guard e == 0 && back[..] == body[..] else { print("quoted_printable: decode_all: ", mime::error_text(e)); exit(1); }

    // A writer fed as the text comes, and a reader fed in pieces of 7
    // bytes, as from a socket: decode, then finish at the end.
    var w = quotedprintable::new_writer();
    var enc: u8[>..] = [];
    var p:   i64     = 0;
    while p < body.len {
        let n = min(10, body.len - p);
        quotedprintable::write(w, enc, body[p..p + n]);
        p += n;
    }
    quotedprintable::close(w, enc);
    guard enc[..] == qp[..] else { print("quoted_printable: the writer differs from encode_all"); exit(1); }
    var r = quotedprintable::new_reader();
    back.clear();
    p = 0;
    while p < enc.len && e == 0 {
        let n = min(7, enc.len - p);
        e = quotedprintable::decode(r, back, enc[p..p + n]);
        p += n;
    }
    if e == 0 { e = quotedprintable::finish(r, back); }
    guard e == 0 && back[..] == body[..] else { print("quoted_printable: the reader failed"); exit(1); }
    print("in pieces: ", body.len, " bytes -> ", enc.len, " -> ", back.len);

    // Binary mode: CR and LF are data too, so they are encoded.
    var bin: u8[>..] = [];
    quotedprintable::encode_all(bin, "a\r\nb", true);
    print("binary: ", bin);
    guard bin[..] == "a=0D=0Ab" else { print("quoted_printable: binary mode"); exit(1); }

    // Go's leniency: a stray '=' that is not followed by hex passes
    // through as itself (the last '=' is a soft line break); a control
    // byte in the body is an error.
    back.clear();
    e = quotedprintable::decode_all(back, "1 + 1 =2 =\r\n");
    print("lenient: \"", back, "\"");
    guard e == 0 && back[..] == "1 + 1 =2 " else { print("quoted_printable: a stray = was refused"); exit(1); }
    var msg: u8[>..] = [];
    back.clear();
    e = quotedprintable::decode_all(back, "bad \x01 byte", msg);
    print("strict: ", msg);
    guard e == mime::ERR_QP_UNESCAPED else { print("quoted_printable: a control byte was taken"); exit(1); }
}
