// The Rust regex crate in the regex benchmark (bench.py): the same protocol
// as bench.goose. regex::bytes with Unicode off: ASCII classes and word
// boundaries on bytes, as gslib's regex has them.
use regex::bytes::{Regex, RegexBuilder};
use std::time::Instant;

fn build(p: &str) -> Regex {
    RegexBuilder::new(p).unicode(false).build().unwrap()
}

// Seconds for the best of the runs of f, by bench.goose's rule.
fn best(mut f: impl FnMut()) -> f64 {
    let (mut best, mut total, mut runs) = (1e9f64, 0f64, 0);
    while runs < 20 && !(runs >= 3 && total >= 0.5) && !(runs >= 1 && total >= 3.0) {
        // a run repeats f until it has taken 5 ms
        let (t0, mut reps, mut t) = (Instant::now(), 0, 0f64);
        while reps == 0 || t < 0.005 {
            f();
            reps += 1;
            t = t0.elapsed().as_secs_f64();
        }
        total += t;
        best = best.min(t / reps as f64);
        runs += 1;
    }
    best
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let table = std::fs::read_to_string(&a[1]).unwrap();
    let text = std::fs::read(&a[2]).unwrap();
    let corpus = &a[3];
    let only = a.get(4);
    let mb = text.len() as f64 / 1e6;
    for line in table.lines() {
        if line.is_empty() || line.starts_with('#') { continue; }
        let f: Vec<&str> = line.split('\t').collect();
        let (name, kind, pattern) = (f[0], f[1], f[2]);
        if only.map_or(false, |o| o != name) { continue; }
        let (mut k, c0) = (0, Instant::now());
        while k < 1 || (c0.elapsed().as_secs_f64() < 0.2 && k < 1000) {
            std::hint::black_box(build(pattern));
            k += 1;
        }
        println!("{} {} compile_us {}", name, corpus, c0.elapsed().as_secs_f64() / k as f64 * 1e6);
        let re = build(pattern);
        let mut n = 0;
        let t = best(|| n = re.find_iter(&text).count());
        println!("{} {} count {}", name, corpus, n);
        println!("{} {} count_mbps {}", name, corpus, mb / t);
        if kind == "caps" {
            let mut sum = 0;
            let t = best(|| {
                sum = 0;
                for c in re.captures_iter(&text) {
                    if let Some(m) = c.get(1) { sum += m.end() - m.start(); }
                }
            });
            println!("{} {} caps_sum {}", name, corpus, sum);
            println!("{} {} caps_mbps {}", name, corpus, mb / t);
        }
    }
}
