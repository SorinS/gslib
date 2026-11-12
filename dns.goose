// dns: the DNS for the Goose language, as Go's github.com/miekg/dns has
// it: messages and the record types miekg implements, their wire form
// (with name compression) and presentation form, zone files, EDNS0, DNSSEC,
// TSIG and SIG(0), dynamic updates, zone transfers, a client and a
// server.
//
//   dns         this module: errors, the numbers of types, classes,
//               rcodes and opcodes with their names, and domain names
//   dns.rdata   each type's rdata: its fields, wire checks, text form
//   dns.msg     records, messages, packing and unpacking, helpers
//   dns.zone    the presentation form read: records and zone files
//   dns.edns    EDNS0: the OPT record and its options
//   dns.dnssec  key tags, DS, RRSIG signing and verification, NSEC3
//   dns.tsig    TSIG (RFC 8945)
//   dns.sig0    SIG(0) (RFC 2931)
//   dns.update  dynamic update (RFC 2136) helpers
//   dns.client  queries over UDP and TCP, resolv.conf, zone transfers in
//   dns.server  serving over UDP and TCP
//
// All of them are in the namespace dns. A domain name is held in its wire
// form, uncompressed: length-prefixed labels and the root's 0, at most 255
// bytes, a Name. Names are compared and hashed in that form; text goes in
// and out at the edges (name_parse, name_text), escaped as RFC 1035 §5.1
// and miekg escape it.

namespace dns;

import std;

// --- Errors -------------------------------------------------------------------
//
// Fallible functions return one of these, OK (0) for success; error_text
// gives miekg's message for each.

let OK: i64 = 0;
let ERR_BUF: i64 = 1;            // a buffer or message too short, or too long for its field
let ERR_RDATA: i64 = 2;          // bad rdata
let ERR_NAME: i64 = 3;           // a malformed domain name, or one longer than 255 bytes
let ERR_FQDN: i64 = 4;           // a name that is not fully qualified where one must be
let ERR_POINTER: i64 = 5;        // a compression pointer loop, or one out of the message
let ERR_SHORT: i64 = 6;          // the message ended inside a record
let ERR_TRAILING: i64 = 7;       // bytes after the last record
let ERR_TYPE: i64 = 8;           // an unknown type mnemonic, or a type with no text form
let ERR_CLASS: i64 = 9;
let ERR_TTL: i64 = 10;
let ERR_SYNTAX: i64 = 11;        // presentation form that does not parse
let ERR_RCODE: i64 = 12;         // an rcode outside 0..4095
let ERR_EXTENDED_RCODE: i64 = 13; // an rcode over 15 without an OPT record
let ERR_ID: i64 = 14;            // a reply whose ID or question is not the query's
let ERR_TRUNCATED: i64 = 15;     // a truncated reply, over TCP too
let ERR_ALG: i64 = 16;           // an algorithm this package does not do
let ERR_KEY: i64 = 17;           // a key unfit for the algorithm, or invalid
let ERR_SIG: i64 = 18;           // a signature that does not verify
let ERR_TIME: i64 = 19;          // a signature outside its validity period
let ERR_NO_SIG: i64 = 20;        // no signature where one must be
let ERR_SECRET: i64 = 21;        // no TSIG secret for the key name
let ERR_AUTH: i64 = 22;          // a TSIG or SIG(0) mismatch: wrong key name or algorithm
let ERR_IO: i64 = 23;            // a socket that could not be opened, read or written
let ERR_TIMEOUT: i64 = 24;
let ERR_SOA: i64 = 25;           // a zone transfer without its SOA where one must be
let ERR_XFR: i64 = 26;           // a zone transfer refused or broken off
let ERR_PRIVATE_KEY: i64 = 27;   // a BIND private-key file that does not parse
let ERR_LIMIT: i64 = 28;         // over a limit: $INCLUDE depth, $GENERATE count, NSEC3 iterations

fn error_text(e: i64) -> const u8[:] {
    if e == OK { return "ok"; }
    if e == ERR_BUF { return "dns: buffer size too small"; }
    if e == ERR_RDATA { return "dns: bad rdata"; }
    if e == ERR_NAME { return "dns: bad domain name"; }
    if e == ERR_FQDN { return "dns: domain must be fully qualified"; }
    if e == ERR_POINTER { return "dns: bad compression pointer"; }
    if e == ERR_SHORT { return "dns: short read"; }
    if e == ERR_TRAILING { return "dns: trailing record rdata"; }
    if e == ERR_TYPE { return "dns: bad rr type"; }
    if e == ERR_CLASS { return "dns: bad class"; }
    if e == ERR_TTL { return "dns: bad ttl"; }
    if e == ERR_SYNTAX { return "dns: syntax error"; }
    if e == ERR_RCODE { return "dns: bad rcode"; }
    if e == ERR_EXTENDED_RCODE { return "dns: bad extended rcode"; }
    if e == ERR_ID { return "dns: id mismatch"; }
    if e == ERR_TRUNCATED { return "dns: failed to unpack truncated message"; }
    if e == ERR_ALG { return "dns: bad algorithm"; }
    if e == ERR_KEY { return "dns: bad key"; }
    if e == ERR_SIG { return "dns: bad signature"; }
    if e == ERR_TIME { return "dns: bad time"; }
    if e == ERR_NO_SIG { return "dns: no signature found"; }
    if e == ERR_SECRET { return "dns: no secrets defined"; }
    if e == ERR_AUTH { return "dns: bad authentication"; }
    if e == ERR_IO { return "dns: i/o error"; }
    if e == ERR_TIMEOUT { return "dns: i/o timeout"; }
    if e == ERR_SOA { return "dns: no SOA"; }
    if e == ERR_XFR { return "dns: zone transfer failed"; }
    if e == ERR_PRIVATE_KEY { return "dns: bad private key"; }
    if e == ERR_LIMIT { return "dns: over a limit"; }
    return "dns: unknown error";
}

// --- Types, classes, rcodes, opcodes ------------------------------------------

let TYPE_NONE: u16 = 0;
let TYPE_A: u16 = 1;
let TYPE_NS: u16 = 2;
let TYPE_MD: u16 = 3;
let TYPE_MF: u16 = 4;
let TYPE_CNAME: u16 = 5;
let TYPE_SOA: u16 = 6;
let TYPE_MB: u16 = 7;
let TYPE_MG: u16 = 8;
let TYPE_MR: u16 = 9;
let TYPE_NULL: u16 = 10;
let TYPE_PTR: u16 = 12;
let TYPE_HINFO: u16 = 13;
let TYPE_MINFO: u16 = 14;
let TYPE_MX: u16 = 15;
let TYPE_TXT: u16 = 16;
let TYPE_RP: u16 = 17;
let TYPE_AFSDB: u16 = 18;
let TYPE_X25: u16 = 19;
let TYPE_ISDN: u16 = 20;
let TYPE_RT: u16 = 21;
let TYPE_NSAPPTR: u16 = 23;
let TYPE_SIG: u16 = 24;
let TYPE_KEY: u16 = 25;
let TYPE_PX: u16 = 26;
let TYPE_GPOS: u16 = 27;
let TYPE_AAAA: u16 = 28;
let TYPE_LOC: u16 = 29;
let TYPE_NXT: u16 = 30;
let TYPE_EID: u16 = 31;
let TYPE_NIMLOC: u16 = 32;
let TYPE_SRV: u16 = 33;
let TYPE_ATMA: u16 = 34;
let TYPE_NAPTR: u16 = 35;
let TYPE_KX: u16 = 36;
let TYPE_CERT: u16 = 37;
let TYPE_DNAME: u16 = 39;
let TYPE_OPT: u16 = 41;
let TYPE_APL: u16 = 42;
let TYPE_DS: u16 = 43;
let TYPE_SSHFP: u16 = 44;
let TYPE_IPSECKEY: u16 = 45;
let TYPE_RRSIG: u16 = 46;
let TYPE_NSEC: u16 = 47;
let TYPE_DNSKEY: u16 = 48;
let TYPE_DHCID: u16 = 49;
let TYPE_NSEC3: u16 = 50;
let TYPE_NSEC3PARAM: u16 = 51;
let TYPE_TLSA: u16 = 52;
let TYPE_SMIMEA: u16 = 53;
let TYPE_HIP: u16 = 55;
let TYPE_NINFO: u16 = 56;
let TYPE_RKEY: u16 = 57;
let TYPE_TALINK: u16 = 58;
let TYPE_CDS: u16 = 59;
let TYPE_CDNSKEY: u16 = 60;
let TYPE_OPENPGPKEY: u16 = 61;
let TYPE_CSYNC: u16 = 62;
let TYPE_ZONEMD: u16 = 63;
let TYPE_SVCB: u16 = 64;
let TYPE_HTTPS: u16 = 65;
let TYPE_SPF: u16 = 99;
let TYPE_UINFO: u16 = 100;
let TYPE_UID: u16 = 101;
let TYPE_GID: u16 = 102;
let TYPE_UNSPEC: u16 = 103;
let TYPE_NID: u16 = 104;
let TYPE_L32: u16 = 105;
let TYPE_L64: u16 = 106;
let TYPE_LP: u16 = 107;
let TYPE_EUI48: u16 = 108;
let TYPE_EUI64: u16 = 109;
let TYPE_NXNAME: u16 = 128;
let TYPE_URI: u16 = 256;
let TYPE_CAA: u16 = 257;
let TYPE_AVC: u16 = 258;
let TYPE_AMTRELAY: u16 = 260;
let TYPE_RESINFO: u16 = 261;
let TYPE_TKEY: u16 = 249;
let TYPE_TSIG: u16 = 250;
let TYPE_IXFR: u16 = 251;
let TYPE_AXFR: u16 = 252;
let TYPE_MAILB: u16 = 253;
let TYPE_MAILA: u16 = 254;
let TYPE_ANY: u16 = 255;
let TYPE_TA: u16 = 32768;
let TYPE_DLV: u16 = 32769;
let TYPE_RESERVED: u16 = 65535;

// Each type's mnemonic, as miekg's TypeToString has them.
let TYPE_CODES: u16[87] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    21, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 39, 41, 42, 43,
    44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
    65, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 128, 256, 257, 258, 260, 261, 249, 250,
    251, 252, 253, 254, 255, 32768, 32769,
];
let TYPE_NAMES: u8[..10][87] = [
    "None", "A", "NS", "MD", "MF", "CNAME", "SOA", "MB", "MG", "MR", "NULL", "PTR", "HINFO", "MINFO", "MX", "TXT", "RP", "AFSDB", "X25", "ISDN",
    "RT", "NSAP-PTR", "SIG", "KEY", "PX", "GPOS", "AAAA", "LOC", "NXT", "EID", "NIMLOC", "SRV", "ATMA", "NAPTR", "KX", "CERT", "DNAME", "OPT", "APL", "DS",
    "SSHFP", "IPSECKEY", "RRSIG", "NSEC", "DNSKEY", "DHCID", "NSEC3", "NSEC3PARAM", "TLSA", "SMIMEA", "HIP", "NINFO", "RKEY", "TALINK", "CDS", "CDNSKEY", "OPENPGPKEY", "CSYNC", "ZONEMD", "SVCB",
    "HTTPS", "SPF", "UINFO", "UID", "GID", "UNSPEC", "NID", "L32", "L64", "LP", "EUI48", "EUI64", "NXNAME", "URI", "CAA", "AVC", "AMTRELAY", "RESINFO", "TKEY", "TSIG",
    "IXFR", "AXFR", "MAILB", "MAILA", "ANY", "TA", "DLV",
];

let CLASS_INET: u16 = 1;
let CLASS_CSNET: u16 = 2;
let CLASS_CHAOS: u16 = 3;
let CLASS_HESIOD: u16 = 4;
let CLASS_NONE: u16 = 254;
let CLASS_ANY: u16 = 255;

let RCODE_SUCCESS: u16 = 0;
let RCODE_FORMAT_ERROR: u16 = 1;
let RCODE_SERVER_FAILURE: u16 = 2;
let RCODE_NAME_ERROR: u16 = 3;      // NXDOMAIN
let RCODE_NOT_IMPLEMENTED: u16 = 4;
let RCODE_REFUSED: u16 = 5;
let RCODE_YXDOMAIN: u16 = 6;
let RCODE_YXRRSET: u16 = 7;
let RCODE_NXRRSET: u16 = 8;
let RCODE_NOT_AUTH: u16 = 9;
let RCODE_NOT_ZONE: u16 = 10;
let RCODE_DSO_TYPE_NI: u16 = 11;
let RCODE_BAD_SIG: u16 = 16;        // and BADVERS
let RCODE_BAD_VERS: u16 = 16;
let RCODE_BAD_KEY: u16 = 17;
let RCODE_BAD_TIME: u16 = 18;
let RCODE_BAD_MODE: u16 = 19;
let RCODE_BAD_NAME: u16 = 20;
let RCODE_BAD_ALG: u16 = 21;
let RCODE_BAD_TRUNC: u16 = 22;
let RCODE_BAD_COOKIE: u16 = 23;

let OPCODE_QUERY: u8 = 0;
let OPCODE_IQUERY: u8 = 1;
let OPCODE_STATUS: u8 = 2;
let OPCODE_NOTIFY: u8 = 4;
let OPCODE_UPDATE: u8 = 5;
let OPCODE_STATEFUL: u8 = 6;

// The type's mnemonic, "TYPEn" for one without (RFC 3597).
fn type_append(out: u8[>..]&, t: u16) {
    for i in TYPE_CODES.len {
        if TYPE_CODES[i] == t { out.append(TYPE_NAMES[i]); return; }
    }
    out.append("TYPE");
    format(out, t);
}

fn type_string(t: u16) -> u8[>..] {
    var out: u8[>..] = [];
    type_append(out, t);
    return out;
}

fn ascii_eq_fold(a: const u8[:], b: const u8[:]) -> bool {
    if a.len != b.len { return false; }
    for i in a.len { if lower(a[i]) != lower(b[i]) { return false; } }
    return true;
}

// The type a mnemonic or "TYPEn" names, -1 for none. Case is ignored.
fn type_from_string(s: const u8[:]) -> i64 {
    for i in TYPE_CODES.len {
        if ascii_eq_fold(s, TYPE_NAMES[i]) && TYPE_CODES[i] != 0 && TYPE_CODES[i] != 65535 { return TYPE_CODES[i]; }
    }
    if s.len > 4 && ascii_eq_fold(s[..4], "TYPE") {
        let n, ok = parse_int(s[4..]);
        if ok && n >= 0 && n <= 65535 && all_digits(s[4..]) { return n; }
    }
    return -1;
}

fn all_digits(s: const u8[:]) -> bool {
    if s.len == 0 { return false; }
    for c in s { if !ascii::is_digit(c) { return false; } }
    return true;
}

// A class's mnemonic as miekg writes it: "ANY" is a type too, so class 255
// is "CLASS255".
fn class_append(out: u8[>..]&, c: u16) {
    if c == CLASS_INET { out.append("IN"); return; }
    if c == CLASS_CSNET { out.append("CS"); return; }
    if c == CLASS_CHAOS { out.append("CH"); return; }
    if c == CLASS_HESIOD { out.append("HS"); return; }
    if c == CLASS_NONE { out.append("NONE"); return; }
    out.append("CLASS");
    format(out, c);
}

fn class_string(c: u16) -> u8[>..] {
    var out: u8[>..] = [];
    class_append(out, c);
    return out;
}

// The class a mnemonic or "CLASSn" names, -1 for none.
fn class_from_string(s: const u8[:]) -> i64 {
    if ascii_eq_fold(s, "IN") { return CLASS_INET; }
    if ascii_eq_fold(s, "CS") { return CLASS_CSNET; }
    if ascii_eq_fold(s, "CH") { return CLASS_CHAOS; }
    if ascii_eq_fold(s, "HS") { return CLASS_HESIOD; }
    if ascii_eq_fold(s, "NONE") { return CLASS_NONE; }
    if ascii_eq_fold(s, "ANY") { return CLASS_ANY; }
    if s.len > 5 && ascii_eq_fold(s[..5], "CLASS") && all_digits(s[5..]) {
        let n, ok = parse_int(s[5..]);
        if ok && n <= 65535 { return n; }
    }
    return -1;
}

let RCODE_NAMES: u8[..9][24] = [
    "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "YXDOMAIN", "YXRRSET",
    "NXRRSET", "NOTAUTH", "NOTZONE", "DSOTYPENI", "", "", "", "",
    "BADSIG", "BADKEY", "BADTIME", "BADMODE", "BADNAME", "BADALG", "BADTRUNC", "BADCOOKIE",
];

// An rcode's name, "" for one without (miekg's RcodeToString).
fn rcode_name(r: u16) -> const u8[:] {
    if r < 24 { return RCODE_NAMES[r]; }
    return "";
}

fn rcode_from_string(s: const u8[:]) -> i64 {
    for i in RCODE_NAMES.len { if RCODE_NAMES[i].len > 0 && ascii_eq_fold(s, RCODE_NAMES[i]) { return i; } }
    if ascii_eq_fold(s, "BADVERS") { return 16; }
    return -1;
}

fn opcode_name(o: u8) -> const u8[:] {
    if o == OPCODE_QUERY { return "QUERY"; }
    if o == OPCODE_IQUERY { return "IQUERY"; }
    if o == OPCODE_STATUS { return "STATUS"; }
    if o == OPCODE_NOTIFY { return "NOTIFY"; }
    if o == OPCODE_UPDATE { return "UPDATE"; }
    return "";
}

// --- Domain names --------------------------------------------------------------
//
// A Name is the wire form, uncompressed: [len label]... 0. The root is [0].

let MAX_NAME: i64 = 255;
let MAX_LABEL: i64 = 63;

type Name = u8[..255];

fn root_name() -> Name { [0] }

// Whether n is a well-formed wire name: labels of 1..63 bytes, a final 0,
// and nothing after it.
fn name_valid(n: const u8[:]) -> bool {
    var i = 0;
    while i < n.len {
        let l = n[i] as i64;
        if l == 0 { return i + 1 == n.len; }
        if l > MAX_LABEL { return false; }
        i += 1 + l;
    }
    return false;
}

// The number of labels, the root not counted (miekg's CountLabel).
fn label_count(n: const u8[:]) -> i64 {
    var c = 0;
    var i = 0;
    while i < n.len && n[i] != 0 { c++; i += 1 + n[i] as i64; }
    return c;
}

// Where each label starts: the offsets of its length bytes.
fn label_offsets(n: const u8[:]) -> i64[..128] {
    var out: i64[..128] = [];
    var i = 0;
    while i < n.len && n[i] != 0 { out.push(i); i += 1 + n[i] as i64; }
    return out;
}

// The name with its first k labels dropped.
fn name_suffix(n: const u8[:], k: i64) -> const u8[:] {
    var i = 0;
    for j in k {
        if i >= n.len || n[i] == 0 { break; }
        i += 1 + n[i] as i64;
    }
    return n[i..];
}

fn name_lower(n: const u8[:]) -> Name {
    var out: Name = [];
    var i = 0;
    while i < n.len {
        let l = n[i] as i64;
        out.push(n[i]);
        for j in l { out.push(lower(n[i + 1 + j])); }
        i += 1 + l;
    }
    return out;
}

fn lower(c: u8) -> u8 { if c >= 'A' && c <= 'Z' { c + 32 } else { c } }

// Equal, ignoring ASCII case (RFC 4343).
fn name_equal(a: const u8[:], b: const u8[:]) -> bool {
    if a.len != b.len { return false; }
    for i in a.len { if lower(a[i]) != lower(b[i]) { return false; } }
    return true;
}

// Whether child is parent or below it (miekg's IsSubDomain).
fn is_subdomain(parent: const u8[:], child: const u8[:]) -> bool {
    let pc = label_count(parent);
    let cc = label_count(child);
    if cc < pc { return false; }
    return name_equal(name_suffix(child, cc - pc), parent);
}

// How many labels, from the right, a and b have in common (miekg's
// CompareDomainName).
fn common_labels(a: const u8[:], b: const u8[:]) -> i64 {
    let ac = label_count(a);
    let bc = label_count(b);
    var n = 0;
    while n < ac && n < bc {
        if !name_equal(name_suffix(a, ac - n - 1), name_suffix(b, bc - n - 1)) { break; }
        n++;
    }
    return n;
}

// RFC 4034 §6.1 canonical order: label by label from the right, each
// compared as lower-cased bytes, a shorter label first. -1, 0 or 1.
fn name_compare(a: const u8[:], b: const u8[:]) -> i64 {
    let ao = label_offsets(a);
    let bo = label_offsets(b);
    var i = ao.len - 1;
    var j = bo.len - 1;
    while i >= 0 && j >= 0 {
        let la = a[ao[i]] as i64;
        let lb = b[bo[j]] as i64;
        let n = if la < lb { la } else { lb };
        for k in n {
            let x = lower(a[ao[i] + 1 + k]);
            let y = lower(b[bo[j] + 1 + k]);
            if x != y { return if x < y { -1 } else { 1 }; }
        }
        if la != lb { return if la < lb { -1 } else { 1 }; }
        i--;
        j--;
    }
    if i >= 0 { return 1; }
    if j >= 0 { return -1; }
    return 0;
}

// a + b: b is appended to a, without a's root. ERR_NAME if over 255 bytes.
fn name_concat(a: const u8[:], b: const u8[:]) -> Name, i64 {
    var out: Name = [];
    if a.len - 1 + b.len > MAX_NAME { return out, ERR_NAME; }
    out.append(a[..a.len - 1]);
    out.append(b);
    return out, OK;
}

// "*." and the name's last k labels (the wildcard an RRSIG's labels
// count names, the one a name below an encloser would match).
fn wildcard_of_labels(n: const u8[:], k: i64) -> Name {
    var out: Name = [1, '*'];
    out.append(name_suffix(n, label_count(n) - k));
    return out;
}

// The name with the first label replaced by "*" (a wildcard's owner).
fn wildcard_of(n: const u8[:]) -> Name {
    var out: Name = [1, '*'];
    out.append(name_suffix(n, 1));
    return out;
}

// --- Names as text ---------------------------------------------------------------

fn name_special(c: u8) -> bool {
    c == '.' || c == ' ' || c == '\'' || c == '@' || c == ';' || c == '(' || c == ')' || c == '"' || c == '\\'
}

// \DDD for a byte.
fn escape_ddd(out: u8[>..]&, c: u8) {
    out.push('\\');
    out.push('0' + c / 100);
    out.push('0' + c / 10 % 10);
    out.push('0' + c % 10);
}

// The text form of a wire name, as miekg's sprintName writes it: "." for
// the root, special characters behind a backslash, unprintable bytes as \DDD.
fn name_append(out: u8[>..]&, n: const u8[:]) {
    if n.len == 0 || n[0] == 0 { out.push('.'); return; }
    var i = 0;
    while i < n.len && n[i] != 0 {
        let l = n[i] as i64;
        for j in l {
            let c = n[i + 1 + j];
            if name_special(c) { out.push('\\'); out.push(c); }
            else if c < ' ' || c > '~' { escape_ddd(out, c); }
            else { out.push(c); }
        }
        out.push('.');
        i += 1 + l;
    }
}

fn name_text(n: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    name_append(out, n);
    return out;
}

fn is_ddd(s: const u8[:], i: i64) -> bool {
    i + 3 <= s.len && ascii::is_digit(s[i]) && ascii::is_digit(s[i + 1]) && ascii::is_digit(s[i + 2])
}

fn ddd(s: const u8[:], i: i64) -> i64 { (s[i] - '0') as i64 * 100 + (s[i + 1] - '0') as i64 * 10 + (s[i + 2] - '0') }

// Whether the text name ends in an unescaped dot (miekg's IsFqdn).
fn is_fqdn(s: const u8[:]) -> bool {
    if s.len == 0 || s[s.len - 1] != '.' { return false; }
    var b = 0;
    var i = s.len - 2;
    while i >= 0 && s[i] == '\\' { b++; i--; }
    return b % 2 == 0;
}

// The text name with a final dot, if it has none (miekg's Fqdn).
fn fqdn(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    out.append(s);
    if !is_fqdn(s) { out.push('.'); }
    return out;
}

// A text name read into its wire form: escapes \X and \DDD, "@" for the
// origin, a relative name (no final dot) followed by the origin. Without
// an origin (empty), a relative name is ERR_FQDN.
fn name_parse(s: const u8[:], origin: const u8[:]) -> Name, i64 {
    var out: Name = [];
    if s == "@" {
        if origin.len == 0 { return out, ERR_FQDN; }
        out.append(origin);
        return out, OK;
    }
    if s == "." { out.push(0); return out, OK; }
    if s.len == 0 { return out, ERR_NAME; }
    var label: u8[..64] = [];
    var buf: u8[..256] = [];
    var absolute = false;
    var i = 0;
    while i < s.len {
        let c = s[i];
        if c == '.' {
            if label.len == 0 { return out, ERR_NAME; }
            if buf.len + 1 + label.len > MAX_NAME { return out, ERR_NAME; }
            buf.push(label.len as! u8);
            buf.append(label);
            label.clear();
            i++;
            if i == s.len { absolute = true; }
            continue;
        }
        var b = c;
        if c == '\\' {
            if i + 1 >= s.len { return out, ERR_NAME; }
            if is_ddd(s, i + 1) {
                let v = ddd(s, i + 1);
                if v > 255 { return out, ERR_NAME; }
                b = v as! u8;
                i += 4;
            } else {
                b = s[i + 1];
                i += 2;
            }
        } else {
            i++;
        }
        if label.len >= MAX_LABEL { return out, ERR_NAME; }
        label.push(b);
    }
    if label.len > 0 {
        if buf.len + 1 + label.len > MAX_NAME { return out, ERR_NAME; }
        buf.push(label.len as! u8);
        buf.append(label);
    }
    if absolute {
        if buf.len + 1 > MAX_NAME { return out, ERR_NAME; }
        out.append(buf);
        out.push(0);
        return out, OK;
    }
    if origin.len == 0 { return out, ERR_FQDN; }
    if buf.len + origin.len > MAX_NAME { return out, ERR_NAME; }
    out.append(buf);
    out.append(origin);
    return out, OK;
}

// The text name lower-cased and made fully qualified (miekg's CanonicalName).
fn canonical_name(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for c in fqdn(s) { out.push(lower(c)); }
    return out;
}

// Whether s is a domain name in text form, and how many labels it has
// (miekg's IsDomainName).
fn is_domain_name(s: const u8[:]) -> i64, bool {
    if s.len == 0 { return 0, false; }
    let n, e = name_parse(s, [0]);
    if e != OK { return 0, false; }
    return label_count(n), true;
}

// The text name split into its labels' text (miekg's SplitDomainName).
fn split_domain_name(s: const u8[:]) -> u8[..252][>..] {
    var out: u8[..252][>..] = [];
    let n, e = name_parse(s, [0]);
    if e != OK { return out; }
    var i = 0;
    while n[i] != 0 {
        let l = n[i] as i64;
        var one: Name = [];
        one.push(l as! u8);
        one.append(n[i + 1 .. i + 1 + l]);
        one.push(0);
        var t = name_text(one);
        var lab: u8[..252] = [];
        lab.append(t[..t.len - 1]);
        out.push(lab);
        i += 1 + l;
    }
    return out;
}

// The reverse-lookup name of an IPv4 (4 bytes) or IPv6 (16 bytes) address
// (miekg's ReverseAddr): "4.3.2.1.in-addr.arpa." or the 32 nibbles and
// "ip6.arpa.".
fn reverse_addr(ip: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let hex = "0123456789abcdef";
    if ip.len == 4 {
        var i = 3;
        while i >= 0 { format(out, ip[i]); out.push('.'); i--; }
        out.append("in-addr.arpa.");
        return out;
    }
    var i = ip.len - 1;
    while i >= 0 {
        out.push(hex[ip[i] & 15]); out.push('.');
        out.push(hex[ip[i] >> 4]); out.push('.');
        i--;
    }
    out.append("ip6.arpa.");
    return out;
}

// --- Wire helpers ---------------------------------------------------------------

fn get16(b: const u8[:], i: i64) -> u16 { (b[i] as u16 << 8) | b[i + 1] }
fn get32(b: const u8[:], i: i64) -> u32 { (b[i] as u32 << 24) | (b[i + 1] as u32 << 16) | (b[i + 2] as u32 << 8) | b[i + 3] }
fn get48(b: const u8[:], i: i64) -> u64 { (get16(b, i) as u64 << 32) | get32(b, i + 2) }
fn get64(b: const u8[:], i: i64) -> u64 { (get32(b, i) as u64 << 32) | get32(b, i + 4) }

fn put16(out: u8[>..]&, v: u16) { out.push((v >> 8) as! u8); out.push(v as! u8); }
fn put32(out: u8[>..]&, v: u32) { put16(out, (v >> 16) as! u16); put16(out, v as! u16); }
fn put48(out: u8[>..]&, v: u64) { put16(out, (v >> 32) as! u16); put32(out, v as! u32); }
fn put64(out: u8[>..]&, v: u64) { put32(out, (v >> 32) as! u32); put32(out, v as! u32); }

fn set16(b: u8[:], i: i64, v: u16) { b[i] = (v >> 8) as! u8; b[i + 1] = v as! u8; }

// Reads a possibly compressed name at off in msg: the name, where the bytes
// after it start, and OK; ERR_POINTER for a pointer loop or one past the
// message, ERR_NAME for a name over 255 bytes, ERR_SHORT if msg ends first.
fn read_name(msg: const u8[:], off: i64) -> Name, i64, i64 {
    var out: Name = [];
    var i = off;
    var end = -1;
    var hops = 0;
    while true {
        if i >= msg.len { return out, 0, ERR_SHORT; }
        let c = msg[i] as i64;
        if c & 0xC0 == 0xC0 {
            if i + 1 >= msg.len { return out, 0, ERR_SHORT; }
            if end < 0 { end = i + 2; }
            hops++;
            if hops > 126 { return out, 0, ERR_POINTER; }
            let p = ((c & 0x3F) << 8) | msg[i + 1];
            if p >= msg.len { return out, 0, ERR_POINTER; }
            i = p;
            continue;
        }
        if c & 0xC0 != 0 { return out, 0, ERR_NAME; }    // 0x40 and 0x80: extended labels, none defined
        if c == 0 {
            if out.len + 1 > MAX_NAME { return out, 0, ERR_NAME; }
            out.push(0);
            if end < 0 { end = i + 1; }
            return out, end, OK;
        }
        if i + 1 + c > msg.len { return out, 0, ERR_SHORT; }
        if out.len + 1 + c + 1 > MAX_NAME { return out, 0, ERR_NAME; }
        out.append(msg[i .. i + 1 + c]);
        i += 1 + c;
    }
    return out, 0, ERR_NAME;
}

// The length of an uncompressed wire name at off, -1 if it is not one.
fn name_len_at(b: const u8[:], off: i64) -> i64 {
    var i = off;
    while i < b.len {
        let l = b[i] as i64;
        if l == 0 { return i + 1 - off; }
        if l > MAX_LABEL { return -1; }
        i += 1 + l;
    }
    return -1;
}
