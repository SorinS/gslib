// Anchors and word boundaries with gslib's regex, std's regex with `^ $ \A
// \z \b \B` and the `m` flag added: whole-text validation, settings read
// line by line, and a whole word replaced but not inside other words. Each
// result is checked.
//
//   goose examples/regex/anchors.goose
import std;
import gslib from "../..";
import gslib.regex;

fn main() {
    // Whole-text validation: \A and \z (or ^ and $ without m) tie the
    // pattern to both ends, where a plain search finds it anywhere.
    let name = regex::compile("""\A[a-z_][a-z0-9_]*\z""");
    for s in ["user_1", "1user", "user-1", "", "ok\n"] {
        var shown: u8[>..] = [];
        format_replaced(shown, s, "\n", "\\n");     // \z does not hold before a final newline
        print("name \"", shown, "\": ", regex::matches(name, s));
    }
    assert(regex::matches(name, "user_1") && !regex::matches(name, "ok\n"));

    // Settings, one per line: under (?m) ^ and $ hold at every line's
    // start and end, so the lines need not be split first.
    let config = "# a comment\nhost: example.com\nport: 8080\n  indented: no\nmode:\n";
    let setting = regex::compile("""(?m)^(\w+):[ \t]*(.*)$""");
    var keys: u8[>..] = [];
    regex::each_captures(setting, config) { c =>
        print("setting ", regex::group(c, 1), " = [", regex::group(c, 2), "]");
        format(keys, regex::group(c, 1), " ");
    };
    assert(keys == "host port mode ");

    // A whole word: \b keeps "cat" from matching inside "concatenate" or
    // "cats".
    let cat = regex::compile("""\bcat\b""");
    var out: u8[>..] = [];
    let text = "cat, cats and concatenate; the cat.";
    regex::format_replaced(out, cat, text) { c => "dog" };
    print(out);
    assert(out == "dog, cats and concatenate; the dog.");
    assert(regex::count(cat, text) == 2);

    // \B: inside a word. Where each word's letters after the first are.
    let inner = regex::compile("""\B\w+""");
    var parts: u8[>..] = [];
    regex::each_match(inner, "go fast") { s, e => format(parts, s, "..", e, " "); };
    print("inside the words: ", parts);
    assert(parts == "1..2 4..7 ");
}
