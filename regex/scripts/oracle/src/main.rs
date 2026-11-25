// The Rust regex crate's answers for regex/scripts/differential.py: for each
// case of the file named (a pattern and a text in hex per line), the line
// regex/test/differential.goose prints: "pattern on text =>" and each
// match's groups as start,end joined by |, "none", or "error" where the
// crate refuses the pattern. regex::bytes with Unicode off: bytes, ASCII
// classes and word boundaries, as gslib's regex has them.
use regex::bytes::RegexBuilder;
use std::io::{BufRead, Write};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn visible(s: &[u8]) -> String {
    String::from_utf8_lossy(s).replace('\n', "\\n").replace('\t', "\\t")
}

fn main() {
    let path = std::env::args().nth(1).expect("a case file");
    let f = std::io::BufReader::new(std::fs::File::open(path).unwrap());
    let out = std::io::stdout();
    let mut out = std::io::BufWriter::new(out.lock());
    for line in f.lines() {
        let line = line.unwrap();
        let (p, t) = line.split_once(' ').unwrap_or((&line, ""));
        let (p, t) = (unhex(p), unhex(t));
        let mut s = format!("{} on {} =>", visible(&p), visible(&t));
        let built = std::str::from_utf8(&p).ok().and_then(|ps| RegexBuilder::new(ps).unicode(false).build().ok());
        match built {
            None => s.push_str(" error"),
            Some(re) => {
                let mut n = 0;
                for c in re.captures_iter(&t) {
                    s.push(' ');
                    for i in 0..c.len() {
                        if i > 0 { s.push('|'); }
                        match c.get(i) {
                            Some(m) => s.push_str(&format!("{},{}", m.start(), m.end())),
                            None => s.push_str("-1,-1"),
                        }
                    }
                    n += 1;
                }
                if n == 0 { s.push_str(" none"); }
            }
        }
        writeln!(out, "{}", s).unwrap();
    }
}
