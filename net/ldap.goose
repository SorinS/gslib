// ldap: LDAPv3 (RFC 4511) for the Goose language, as Go's
// github.com/go-ldap/ldap/v3 has it, on asn1 for the BER. This module
// holds the protocol's numbers, the result codes and their names, the
// encoding of every request and control, and the reading of responses:
// a message is checked whole when it arrives, and then read in place,
// its parts asn1::Tlv offsets into the bytes it came in. ldap.conn keeps
// a connection's state (message IDs, outstanding requests, StartTLS) and
// frames messages out of a byte stream; ldap.filter, ldap.dn, ldap.url
// and ldap.ldif are the string forms (RFC 4515, 4514, 4516, 2849).
// Nothing here does I/O.

namespace ldap;

import std;
import encoding.asn1;
import crypto.bignum;

// protocolOp tags (RFC 4511 §4.2-4.14): [APPLICATION n], as identifier octets.
let OP_BIND_REQUEST: u32 = 0x60;
let OP_BIND_RESPONSE: u32 = 0x61;
let OP_UNBIND_REQUEST: u32 = 0x42;
let OP_SEARCH_REQUEST: u32 = 0x63;
let OP_SEARCH_ENTRY: u32 = 0x64;
let OP_SEARCH_DONE: u32 = 0x65;
let OP_MODIFY_REQUEST: u32 = 0x66;
let OP_MODIFY_RESPONSE: u32 = 0x67;
let OP_ADD_REQUEST: u32 = 0x68;
let OP_ADD_RESPONSE: u32 = 0x69;
let OP_DELETE_REQUEST: u32 = 0x4a;
let OP_DELETE_RESPONSE: u32 = 0x6b;
let OP_MODDN_REQUEST: u32 = 0x6c;
let OP_MODDN_RESPONSE: u32 = 0x6d;
let OP_COMPARE_REQUEST: u32 = 0x6e;
let OP_COMPARE_RESPONSE: u32 = 0x6f;
let OP_ABANDON_REQUEST: u32 = 0x50;
let OP_SEARCH_REFERENCE: u32 = 0x73;
let OP_EXTENDED_REQUEST: u32 = 0x77;
let OP_EXTENDED_RESPONSE: u32 = 0x78;
let OP_INTERMEDIATE: u32 = 0x79;

// The response a request gets, 0 for unbind and abandon, which get none.
fn response_op(request: u32) -> u32 {
    if request == OP_BIND_REQUEST { return OP_BIND_RESPONSE; }
    if request == OP_SEARCH_REQUEST { return OP_SEARCH_DONE; }
    if request == OP_MODIFY_REQUEST { return OP_MODIFY_RESPONSE; }
    if request == OP_ADD_REQUEST { return OP_ADD_RESPONSE; }
    if request == OP_DELETE_REQUEST { return OP_DELETE_RESPONSE; }
    if request == OP_MODDN_REQUEST { return OP_MODDN_RESPONSE; }
    if request == OP_COMPARE_REQUEST { return OP_COMPARE_RESPONSE; }
    if request == OP_EXTENDED_REQUEST { return OP_EXTENDED_RESPONSE; }
    return 0;
}

// Search scopes (§4.5.1.2; children is draft-sermersheim-ldap-subordinate-scope).
let SCOPE_BASE: i64 = 0;
let SCOPE_ONE: i64 = 1;
let SCOPE_SUB: i64 = 2;
let SCOPE_CHILDREN: i64 = 3;

// derefAliases.
let DEREF_NEVER: i64 = 0;
let DEREF_SEARCHING: i64 = 1;
let DEREF_FINDING: i64 = 2;
let DEREF_ALWAYS: i64 = 3;

// Modify operations (§4.6; increment is RFC 4525).
let MOD_ADD: i64 = 0;
let MOD_DELETE: i64 = 1;
let MOD_REPLACE: i64 = 2;
let MOD_INCREMENT: i64 = 3;

// Result codes (§4.1.9, Appendix A, and the registrations since).
let RESULT_SUCCESS: i64 = 0;
let RESULT_OPERATIONS_ERROR: i64 = 1;
let RESULT_PROTOCOL_ERROR: i64 = 2;
let RESULT_TIME_LIMIT_EXCEEDED: i64 = 3;
let RESULT_SIZE_LIMIT_EXCEEDED: i64 = 4;
let RESULT_COMPARE_FALSE: i64 = 5;
let RESULT_COMPARE_TRUE: i64 = 6;
let RESULT_AUTH_METHOD_NOT_SUPPORTED: i64 = 7;
let RESULT_STRONG_AUTH_REQUIRED: i64 = 8;
let RESULT_REFERRAL: i64 = 10;
let RESULT_ADMIN_LIMIT_EXCEEDED: i64 = 11;
let RESULT_UNAVAILABLE_CRITICAL_EXTENSION: i64 = 12;
let RESULT_CONFIDENTIALITY_REQUIRED: i64 = 13;
let RESULT_SASL_BIND_IN_PROGRESS: i64 = 14;
let RESULT_NO_SUCH_ATTRIBUTE: i64 = 16;
let RESULT_UNDEFINED_ATTRIBUTE_TYPE: i64 = 17;
let RESULT_INAPPROPRIATE_MATCHING: i64 = 18;
let RESULT_CONSTRAINT_VIOLATION: i64 = 19;
let RESULT_ATTRIBUTE_OR_VALUE_EXISTS: i64 = 20;
let RESULT_INVALID_ATTRIBUTE_SYNTAX: i64 = 21;
let RESULT_NO_SUCH_OBJECT: i64 = 32;
let RESULT_ALIAS_PROBLEM: i64 = 33;
let RESULT_INVALID_DN_SYNTAX: i64 = 34;
let RESULT_IS_LEAF: i64 = 35;
let RESULT_ALIAS_DEREFERENCING_PROBLEM: i64 = 36;
let RESULT_INAPPROPRIATE_AUTHENTICATION: i64 = 48;
let RESULT_INVALID_CREDENTIALS: i64 = 49;
let RESULT_INSUFFICIENT_ACCESS_RIGHTS: i64 = 50;
let RESULT_BUSY: i64 = 51;
let RESULT_UNAVAILABLE: i64 = 52;
let RESULT_UNWILLING_TO_PERFORM: i64 = 53;
let RESULT_LOOP_DETECT: i64 = 54;
let RESULT_SORT_CONTROL_MISSING: i64 = 60;
let RESULT_OFFSET_RANGE_ERROR: i64 = 61;
let RESULT_NAMING_VIOLATION: i64 = 64;
let RESULT_OBJECT_CLASS_VIOLATION: i64 = 65;
let RESULT_NOT_ALLOWED_ON_NON_LEAF: i64 = 66;
let RESULT_NOT_ALLOWED_ON_RDN: i64 = 67;
let RESULT_ENTRY_ALREADY_EXISTS: i64 = 68;
let RESULT_OBJECT_CLASS_MODS_PROHIBITED: i64 = 69;
let RESULT_RESULTS_TOO_LARGE: i64 = 70;
let RESULT_AFFECTS_MULTIPLE_DSAS: i64 = 71;
let RESULT_VLV_ERROR: i64 = 76;
let RESULT_OTHER: i64 = 80;
let RESULT_CANCELED: i64 = 118;
let RESULT_NO_SUCH_OPERATION: i64 = 119;
let RESULT_TOO_LATE: i64 = 120;
let RESULT_CANNOT_CANCEL: i64 = 121;
let RESULT_ASSERTION_FAILED: i64 = 122;
let RESULT_AUTHORIZATION_DENIED: i64 = 123;
let RESULT_SYNC_REFRESH_REQUIRED: i64 = 4096;

// The client's own codes, the C API's (RFC 1823 and its drafts) and
// go-ldap's (200 on).
let RESULT_SERVER_DOWN: i64 = 81;
let RESULT_LOCAL_ERROR: i64 = 82;
let RESULT_ENCODING_ERROR: i64 = 83;
let RESULT_DECODING_ERROR: i64 = 84;
let RESULT_TIMEOUT: i64 = 85;
let RESULT_AUTH_UNKNOWN: i64 = 86;
let RESULT_FILTER_ERROR: i64 = 87;
let RESULT_USER_CANCELED: i64 = 88;
let RESULT_PARAM_ERROR: i64 = 89;
let RESULT_NO_MEMORY: i64 = 90;
let RESULT_CONNECT_ERROR: i64 = 91;
let RESULT_NOT_SUPPORTED: i64 = 92;
let RESULT_CONTROL_NOT_FOUND: i64 = 93;
let RESULT_NO_RESULTS_RETURNED: i64 = 94;
let RESULT_MORE_RESULTS_TO_RETURN: i64 = 95;
let RESULT_CLIENT_LOOP: i64 = 96;
let RESULT_REFERRAL_LIMIT_EXCEEDED: i64 = 97;
let RESULT_INVALID_RESPONSE: i64 = 100;
let RESULT_AMBIGUOUS_RESPONSE: i64 = 101;
let RESULT_TLS_NOT_SUPPORTED: i64 = 112;
let RESULT_INTERMEDIATE_RESPONSE: i64 = 113;
let RESULT_UNKNOWN_TYPE: i64 = 114;
let ERROR_NETWORK: i64 = 200;
let ERROR_FILTER_COMPILE: i64 = 201;
let ERROR_FILTER_DECOMPILE: i64 = 202;
let ERROR_UNEXPECTED_MESSAGE: i64 = 204;
let ERROR_UNEXPECTED_RESPONSE: i64 = 205;
let ERROR_EMPTY_PASSWORD: i64 = 206;

// A result code's name, as go-ldap's LDAPResultCodeMap has it ("" for
// one it does not know).
fn result_name(code: i64) -> const u8[:] {
    if code == 0 { return "Success"; }
    if code == 1 { return "Operations Error"; }
    if code == 2 { return "Protocol Error"; }
    if code == 3 { return "Time Limit Exceeded"; }
    if code == 4 { return "Size Limit Exceeded"; }
    if code == 5 { return "Compare False"; }
    if code == 6 { return "Compare True"; }
    if code == 7 { return "Auth Method Not Supported"; }
    if code == 8 { return "Strong Auth Required"; }
    if code == 10 { return "Referral"; }
    if code == 11 { return "Admin Limit Exceeded"; }
    if code == 12 { return "Unavailable Critical Extension"; }
    if code == 13 { return "Confidentiality Required"; }
    if code == 14 { return "Sasl Bind In Progress"; }
    if code == 16 { return "No Such Attribute"; }
    if code == 17 { return "Undefined Attribute Type"; }
    if code == 18 { return "Inappropriate Matching"; }
    if code == 19 { return "Constraint Violation"; }
    if code == 20 { return "Attribute Or Value Exists"; }
    if code == 21 { return "Invalid Attribute Syntax"; }
    if code == 32 { return "No Such Object"; }
    if code == 33 { return "Alias Problem"; }
    if code == 34 { return "Invalid DN Syntax"; }
    if code == 35 { return "Is Leaf"; }
    if code == 36 { return "Alias Dereferencing Problem"; }
    if code == 48 { return "Inappropriate Authentication"; }
    if code == 49 { return "Invalid Credentials"; }
    if code == 50 { return "Insufficient Access Rights"; }
    if code == 51 { return "Busy"; }
    if code == 52 { return "Unavailable"; }
    if code == 53 { return "Unwilling To Perform"; }
    if code == 54 { return "Loop Detect"; }
    if code == 60 { return "Sort Control Missing"; }
    if code == 61 { return "Result Offset Range Error"; }
    if code == 64 { return "Naming Violation"; }
    if code == 65 { return "Object Class Violation"; }
    if code == 66 { return "Not Allowed On Non Leaf"; }
    if code == 67 { return "Not Allowed On RDN"; }
    if code == 68 { return "Entry Already Exists"; }
    if code == 69 { return "Object Class Mods Prohibited"; }
    if code == 70 { return "Results Too Large"; }
    if code == 71 { return "Affects Multiple DSAs"; }
    if code == 76 { return "Failed because of a problem related to the virtual list view"; }
    if code == 80 { return "Other"; }
    if code == 81 { return "Cannot establish a connection"; }
    if code == 82 { return "An error occurred"; }
    if code == 83 { return "LDAP encountered an error while encoding"; }
    if code == 84 { return "LDAP encountered an error while decoding"; }
    if code == 85 { return "LDAP timeout while waiting for a response from the server"; }
    if code == 86 { return "The auth method requested in a bind request is unknown"; }
    if code == 87 { return "An error occurred while encoding the given search filter"; }
    if code == 88 { return "The user canceled the operation"; }
    if code == 89 { return "An invalid parameter was specified"; }
    if code == 90 { return "Out of memory error"; }
    if code == 91 { return "A connection to the server could not be established"; }
    if code == 92 { return "An attempt has been made to use a feature not supported LDAP"; }
    if code == 93 { return "The controls required to perform the requested operation were not found"; }
    if code == 94 { return "No results were returned from the server"; }
    if code == 95 { return "There are more results in the chain of results"; }
    if code == 96 { return "A loop has been detected. For example when following referrals"; }
    if code == 97 { return "The referral hop limit has been exceeded"; }
    if code == 100 { return "Invalid Response"; }
    if code == 101 { return "Ambiguous Response"; }
    if code == 112 { return "Tls Not Supported"; }
    if code == 113 { return "Intermediate Response"; }
    if code == 114 { return "Unknown Type"; }
    if code == 118 { return "Operation was canceled"; }
    if code == 119 { return "Server has no knowledge of the operation requested for cancellation"; }
    if code == 120 { return "Too late to cancel the outstanding operation"; }
    if code == 121 { return "The identified operation does not support cancellation or the cancel operation cannot be performed"; }
    if code == 122 { return "An assertion control given in the LDAP operation evaluated to false causing the operation to not be performed"; }
    if code == 123 { return "Authorization Denied"; }
    if code == 4096 { return "Refresh Required"; }
    if code == 200 { return "Network Error"; }
    if code == 201 { return "Filter Compile Error"; }
    if code == 202 { return "Filter Decompile Error"; }
    if code == 203 { return "Debugging Error"; }
    if code == 204 { return "Unexpected Message"; }
    if code == 205 { return "Unexpected Response"; }
    if code == 206 { return "Empty password not allowed by the client"; }
    return "";
}

// An error as go-ldap's Error.Error() writes it:
// LDAP Result Code 49 "Invalid Credentials": <message>
fn error_text(code: i64, message: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    format(out, "LDAP Result Code ", code, " \"", result_name(code), "\": ", message);
    return out;
}

// Extended operations, unsolicited notifications and features.
let OID_START_TLS: const u8[:] = "1.3.6.1.4.1.1466.20037";         // RFC 4511 §4.14
let OID_NOTICE_OF_DISCONNECTION: const u8[:] = "1.3.6.1.4.1.1466.20036";  // §4.4.1
let OID_WHO_AM_I: const u8[:] = "1.3.6.1.4.1.4203.1.11.3";         // RFC 4532
let OID_PASSWORD_MODIFY: const u8[:] = "1.3.6.1.4.1.4203.1.11.1";  // RFC 3062
let OID_CANCEL: const u8[:] = "1.3.6.1.1.8";                       // RFC 3909

// Controls: go-ldap's, and a few more.
let CONTROL_PAGING: const u8[:] = "1.2.840.113556.1.4.319";                   // RFC 2696
let CONTROL_BEHERA_PASSWORD_POLICY: const u8[:] = "1.3.6.1.4.1.42.2.27.8.5.1"; // draft-behera-ldap-password-policy
let CONTROL_VCHU_PASSWORD_MUST_CHANGE: const u8[:] = "2.16.840.1.113730.3.4.4";
let CONTROL_VCHU_PASSWORD_WARNING: const u8[:] = "2.16.840.1.113730.3.4.5";
let CONTROL_MANAGE_DSA_IT: const u8[:] = "2.16.840.1.113730.3.4.2";           // RFC 3296
let CONTROL_SUBTREE_DELETE: const u8[:] = "1.2.840.113556.1.4.805";
let CONTROL_MICROSOFT_NOTIFICATION: const u8[:] = "1.2.840.113556.1.4.528";
let CONTROL_MICROSOFT_SHOW_DELETED: const u8[:] = "1.2.840.113556.1.4.417";
let CONTROL_MICROSOFT_SERVER_LINK_TTL: const u8[:] = "1.2.840.113556.1.4.2309";
let CONTROL_PROXIED_AUTHZ: const u8[:] = "2.16.840.1.113730.3.4.18";          // RFC 4370
let CONTROL_SORT_REQUEST: const u8[:] = "1.2.840.113556.1.4.473";             // RFC 2891
let CONTROL_SORT_RESPONSE: const u8[:] = "1.2.840.113556.1.4.474";
let CONTROL_ASSERTION: const u8[:] = "1.3.6.1.1.12";                          // RFC 4528
let CONTROL_AUTHZ_ID_REQUEST: const u8[:] = "2.16.840.1.113730.3.4.16";       // RFC 3829
let CONTROL_AUTHZ_ID_RESPONSE: const u8[:] = "2.16.840.1.113730.3.4.15";

// A control's name, as go-ldap's ControlTypeMap has it, or "".
fn control_name(oid: const u8[:]) -> const u8[:] {
    if oid == CONTROL_PAGING { return "Paging"; }
    if oid == CONTROL_BEHERA_PASSWORD_POLICY { return "Password Policy - Behera Draft"; }
    if oid == CONTROL_MANAGE_DSA_IT { return "Manage DSA IT"; }
    if oid == CONTROL_SUBTREE_DELETE { return "Subtree Delete Control"; }
    if oid == CONTROL_MICROSOFT_NOTIFICATION { return "Change Notification - Microsoft"; }
    if oid == CONTROL_MICROSOFT_SHOW_DELETED { return "Show Deleted Objects - Microsoft"; }
    if oid == CONTROL_MICROSOFT_SERVER_LINK_TTL { return "Return TTL-DNs for link values with associated expiry times - Microsoft"; }
    return "";
}

// Behera password policy errors (the response control's error field).
let PPOLICY_PASSWORD_EXPIRED: i64 = 0;
let PPOLICY_ACCOUNT_LOCKED: i64 = 1;
let PPOLICY_CHANGE_AFTER_RESET: i64 = 2;
let PPOLICY_MODIFICATIONS_NOT_ALLOWED: i64 = 3;
let PPOLICY_MUST_SUPPLY_OLD_PASSWORD: i64 = 4;
let PPOLICY_INSUFFICIENT_QUALITY: i64 = 5;
let PPOLICY_TOO_SHORT: i64 = 6;
let PPOLICY_TOO_YOUNG: i64 = 7;
let PPOLICY_IN_HISTORY: i64 = 8;

// The error's text, as go-ldap's BeheraPasswordPolicyErrorMap has it.
fn ppolicy_error_name(e: i64) -> const u8[:] {
    if e == 0 { return "Password expired"; }
    if e == 1 { return "Account locked"; }
    if e == 2 { return "Password must be changed"; }
    if e == 3 { return "Policy prevents password modification"; }
    if e == 4 { return "Policy requires old password in order to change password"; }
    if e == 5 { return "Password fails quality checks"; }
    if e == 6 { return "Password is too short for policy"; }
    if e == 7 { return "Password has been changed too recently"; }
    if e == 8 { return "New password is in list of old passwords"; }
    return "";
}

// --- Writing requests ---------------------------------------------------------

// The context tags of the protocol, as identifier octets.
fn ctx_prim(n: u32) -> u32 { 0x80 | n }
fn ctx_cons(n: u32) -> u32 { 0xa0 | n }

// An LDAPMessage: the ID, the protocolOp (its tag and content) and the
// controls (Control SEQUENCEs one after another; none when empty).
fn put_message(out: u8[>..]&, id: i64, op: u32, body: const u8[:], controls: const u8[:]) {
    var m: u8[>..] = [];
    asn1::put_i64(m, id);
    asn1::put(m, op, body);
    if controls.len > 0 { asn1::put(m, ctx_cons(0), controls); }
    asn1::put(out, asn1::SEQUENCE, m);
}

fn put_enum(out: u8[>..]&, v: i64) { asn1::put_i64(out, v, asn1::ENUMERATED); }

// BindRequest with simple authentication (§4.2): version 3, the name,
// [0] the password.
fn bind_body(dn: const u8[:], password: const u8[:]) -> u8[>..] {
    var b: u8[>..] = [];
    asn1::put_i64(b, 3);
    asn1::put_octets(b, dn);
    asn1::put(b, ctx_prim(0), password);
    return b;
}

// BindRequest with SASL (§4.2, RFC 4513 §5.2): [3] { mechanism,
// credentials if any }.
fn sasl_bind_body(mechanism: const u8[:], credentials: const u8[:], has_credentials: bool) -> u8[>..] {
    var b: u8[>..] = [];
    asn1::put_i64(b, 3);
    asn1::put_octets(b, "");
    var s: u8[>..] = [];
    asn1::put_octets(s, mechanism);
    if has_credentials { asn1::put_octets(s, credentials); }
    asn1::put(b, ctx_cons(3), s);
    return b;
}

// The attribute selection of a search: names separated by commas or
// spaces (an attribute description holds neither), "*", "+" or "1.1".
fn put_attribute_list(out: u8[>..]&, attrs: const u8[:]) {
    var s: u8[>..] = [];
    var i = 0;
    while i < attrs.len {
        while i < attrs.len && (attrs[i] == ',' || attrs[i] == ' ') { i++; }
        let from = i;
        while i < attrs.len && attrs[i] != ',' && attrs[i] != ' ' { i++; }
        if i > from { asn1::put_octets(s, attrs[from..i]); }
    }
    asn1::put(out, asn1::SEQUENCE, s);
}

// SearchRequest (§4.5.1), the filter already compiled (ldap.filter).
fn search_body(base: const u8[:], scope: i64, deref: i64, size_limit: i64, time_limit: i64, types_only: bool,
               filter: const u8[:], attrs: const u8[:]) -> u8[>..] {
    var b: u8[>..] = [];
    asn1::put_octets(b, base);
    put_enum(b, scope);
    put_enum(b, deref);
    asn1::put_i64(b, size_limit);
    asn1::put_i64(b, time_limit);
    asn1::put_bool(b, types_only);
    b.append(filter);
    put_attribute_list(b, attrs);
    return b;
}

// A value of an attribute, for put_attribute and put_change: they take
// the values one after another, as put_value writes them.
fn put_value(out: u8[>..]&, v: const u8[:]) { asn1::put_octets(out, v); }

// An Attribute or PartialAttribute (§4.1.7): the type and SET OF values.
fn put_attribute(out: u8[>..]&, name: const u8[:], values: const u8[:]) {
    var a: u8[>..] = [];
    asn1::put_octets(a, name);
    asn1::put(a, asn1::SET, values);
    asn1::put(out, asn1::SEQUENCE, a);
}

// One change of a ModifyRequest (§4.6): the operation and the
// attribute with its values (put_value's, one after another).
fn put_change(out: u8[>..]&, operation: i64, name: const u8[:], values: const u8[:]) {
    var c: u8[>..] = [];
    put_enum(c, operation);
    put_attribute(c, name, values);
    asn1::put(out, asn1::SEQUENCE, c);
}

// ModifyRequest: the object and the changes (put_change's).
fn modify_body(dn: const u8[:], changes: const u8[:]) -> u8[>..] {
    var b: u8[>..] = [];
    asn1::put_octets(b, dn);
    asn1::put(b, asn1::SEQUENCE, changes);
    return b;
}

// AddRequest: the entry and its attributes (put_attribute's).
fn add_body(dn: const u8[:], attributes: const u8[:]) -> u8[>..] {
    var b: u8[>..] = [];
    asn1::put_octets(b, dn);
    asn1::put(b, asn1::SEQUENCE, attributes);
    return b;
}

// ModifyDNRequest: the entry, its new RDN, whether the old RDN's values
// go, and [0] the new superior ("" for none).
fn moddn_body(dn: const u8[:], new_rdn: const u8[:], delete_old: bool, new_superior: const u8[:]) -> u8[>..] {
    var b: u8[>..] = [];
    asn1::put_octets(b, dn);
    asn1::put_octets(b, new_rdn);
    asn1::put_bool(b, delete_old);
    if new_superior.len > 0 { asn1::put(b, ctx_prim(0), new_superior); }
    return b;
}

// CompareRequest: the entry and an AttributeValueAssertion.
fn compare_body(dn: const u8[:], attr: const u8[:], value: const u8[:]) -> u8[>..] {
    var b: u8[>..] = [];
    asn1::put_octets(b, dn);
    var ava: u8[>..] = [];
    asn1::put_octets(ava, attr);
    asn1::put_octets(ava, value);
    asn1::put(b, asn1::SEQUENCE, ava);
    return b;
}

// ExtendedRequest: [0] the OID, [1] the value if any.
fn extended_body(oid: const u8[:], value: const u8[:], has_value: bool) -> u8[>..] {
    var b: u8[>..] = [];
    asn1::put(b, ctx_prim(0), oid);
    if has_value { asn1::put(b, ctx_prim(1), value); }
    return b;
}

// The Password Modify request's value (RFC 3062): [0] the user, [1] the
// old password, [2] the new, each left out when empty.
fn password_modify_value(user: const u8[:], old_password: const u8[:], new_password: const u8[:]) -> u8[>..] {
    var s: u8[>..] = [];
    if user.len > 0 { asn1::put(s, ctx_prim(0), user); }
    if old_password.len > 0 { asn1::put(s, ctx_prim(1), old_password); }
    if new_password.len > 0 { asn1::put(s, ctx_prim(2), new_password); }
    var v: u8[>..] = [];
    asn1::put(v, asn1::SEQUENCE, s);
    return v;
}

// The AbandonRequest's (and the Cancel operation's) message ID.
fn abandon_body(id: i64) -> u8[>..] {
    var b: u8[>..] = [];
    var m: u8[>..] = [];
    asn1::put_i64(m, id);
    let t, ok = asn1::parse(m);
    b.append(m[t.off..t.end]);
    return b;
}

fn cancel_value(id: i64) -> u8[>..] {
    var s: u8[>..] = [];
    asn1::put_i64(s, id);
    var v: u8[>..] = [];
    asn1::put(v, asn1::SEQUENCE, s);
    return v;
}

// --- Controls -------------------------------------------------------------------

// A Control (§4.1.11): the OID, the criticality when true, the value if any.
fn put_control(out: u8[>..]&, oid: const u8[:], critical: bool, value: const u8[:], has_value: bool) {
    var c: u8[>..] = [];
    asn1::put_octets(c, oid);
    if critical { asn1::put_bool(c, true); }
    if has_value { asn1::put_octets(c, value); }
    asn1::put(out, asn1::SEQUENCE, c);
}

// Simple paged results (RFC 2696): the page size and the cookie of the
// last page's response ("" for the first).
fn put_paging(out: u8[>..]&, size: i64, cookie: const u8[:], critical: bool = false) {
    var s: u8[>..] = [];
    asn1::put_i64(s, size);
    asn1::put_octets(s, cookie);
    var v: u8[>..] = [];
    asn1::put(v, asn1::SEQUENCE, s);
    put_control(out, CONTROL_PAGING, critical, v, true);
}

// ManageDsaIT (RFC 3296): referral objects as ordinary entries.
fn put_manage_dsa_it(out: u8[>..]&, critical: bool) { put_control(out, CONTROL_MANAGE_DSA_IT, critical, "", false); }

fn put_subtree_delete(out: u8[>..]&) { put_control(out, CONTROL_SUBTREE_DELETE, false, "", false); }

// The request for the Behera password policy response.
fn put_ppolicy_request(out: u8[>..]&) { put_control(out, CONTROL_BEHERA_PASSWORD_POLICY, false, "", false); }

// Proxied authorization (RFC 4370): the operation as authzid ("dn:..." or
// "u:..."), always critical.
fn put_proxied_authz(out: u8[>..]&, authzid: const u8[:]) { put_control(out, CONTROL_PROXIED_AUTHZ, true, authzid, true); }

// Authorization identity request (RFC 3829), with a bind.
fn put_authz_id_request(out: u8[>..]&) { put_control(out, CONTROL_AUTHZ_ID_REQUEST, false, "", false); }

// Assertion (RFC 4528): the operation only if the entry matches the
// compiled filter.
fn put_assertion(out: u8[>..]&, filter: const u8[:], critical: bool = true) {
    put_control(out, CONTROL_ASSERTION, critical, filter, true);
}

// Server-side sorting (RFC 2891): keys separated by commas or spaces,
// each [-]attribute[:orderingRule], "-" for reverse order, as
// ldapsearch's -E sss= takes them.
fn put_sort(out: u8[>..]&, keys: const u8[:], critical: bool = false) {
    var list: u8[>..] = [];
    var i = 0;
    while i < keys.len {
        while i < keys.len && (keys[i] == ',' || keys[i] == ' ') { i++; }
        let from = i;
        while i < keys.len && keys[i] != ',' && keys[i] != ' ' { i++; }
        if i == from { continue; }
        var a = from;
        let reverse = keys[a] == '-';
        if reverse { a++; }
        var name_end = i;
        let colon = position(keys[a..i], ':');
        if colon >= 0 { name_end = a + colon; }
        var s: u8[>..] = [];
        asn1::put_octets(s, keys[a..name_end]);
        if name_end + 1 < i { asn1::put(s, ctx_prim(0), keys[name_end + 1..i]); }
        if reverse { var t: u8[1] = [0xff]; asn1::put(s, ctx_prim(1), t); }
        asn1::put(list, asn1::SEQUENCE, s);
    }
    var v: u8[>..] = [];
    asn1::put(v, asn1::SEQUENCE, list);
    put_control(out, CONTROL_SORT_REQUEST, critical, v, true);
}

// --- Reading responses ------------------------------------------------------------

// One LDAPMessage: its ID, the protocolOp's tag, where the message is in
// the buffer, the protocolOp, and the controls if any.
struct Message { id: i64, op: u32, start: i64, end: i64, body: asn1::Tlv, controls: asn1::Tlv, has_controls: bool }

// The content of an element, as the bytes it is.
fn bytes(buf: const u8[:], t: asn1::Tlv) -> const u8[:] { buf[t.off..t.end] }

fn octets_ok(t: asn1::Tlv) -> bool { t.tag == asn1::OCTET_STRING }

// An LDAPResult's components, from the response's children.
fn result_ok(buf: const u8[:], cs: const asn1::Tlv[:]) -> bool {
    if cs.len < 3 { return false; }
    let code, ok = asn1::read_i64(buf, cs[0], asn1::ENUMERATED, true);
    if !ok || code < 0 || !octets_ok(cs[1]) || !octets_ok(cs[2]) { return false; }
    if cs.len > 3 && cs[3].tag == ctx_cons(3) {
        let urls, oku = asn1::children(buf, cs[3], true);
        if !oku || urls.len == 0 { return false; }
        for u in urls { if !octets_ok(u) { return false; } }
    }
    return true;
}

// Whether a protocolOp a client can get is well formed, all the way down.
fn body_ok(buf: const u8[:], op: u32, b: asn1::Tlv) -> bool {
    if op == OP_SEARCH_ENTRY {
        let cs, ok = asn1::children(buf, b, true);
        if !ok || cs.len != 2 || !octets_ok(cs[0]) || cs[1].tag != asn1::SEQUENCE { return false; }
        let attrs, oka = asn1::children(buf, cs[1], true);
        if !oka { return false; }
        for a in attrs {
            let parts, okp = asn1::children(buf, a, true);
            if !okp || a.tag != asn1::SEQUENCE || parts.len != 2 || !octets_ok(parts[0]) || parts[1].tag != asn1::SET { return false; }
            let vals, okv = asn1::children(buf, parts[1], true);
            if !okv { return false; }
            for v in vals { if !octets_ok(v) { return false; } }
        }
        return true;
    }
    if op == OP_SEARCH_REFERENCE {
        let urls, ok = asn1::children(buf, b, true);
        if !ok || urls.len == 0 { return false; }
        for u in urls { if !octets_ok(u) { return false; } }
        return true;
    }
    if op == OP_INTERMEDIATE {
        let cs, ok = asn1::children(buf, b, true);
        if !ok { return false; }
        var i = 0;
        if i < cs.len && cs[i].tag == ctx_prim(0) { i++; }
        if i < cs.len && cs[i].tag == ctx_prim(1) { i++; }
        return i == cs.len;
    }
    if op == OP_BIND_RESPONSE || op == OP_SEARCH_DONE || op == OP_MODIFY_RESPONSE || op == OP_ADD_RESPONSE ||
       op == OP_DELETE_RESPONSE || op == OP_MODDN_RESPONSE || op == OP_COMPARE_RESPONSE || op == OP_EXTENDED_RESPONSE {
        let cs, ok = asn1::children(buf, b, true);
        if !ok || !result_ok(buf, cs) { return false; }
        var i = if cs.len > 3 && cs[3].tag == ctx_cons(3) { 4 } else { 3 };
        // What follows the LDAPResult: serverSaslCreds [7] for a bind,
        // responseName [10] and responseValue [11] for an extended one.
        if op == OP_BIND_RESPONSE && i < cs.len && cs[i].tag == ctx_prim(7) { i++; }
        if op == OP_EXTENDED_RESPONSE {
            if i < cs.len && cs[i].tag == ctx_prim(10) { i++; }
            if i < cs.len && cs[i].tag == ctx_prim(11) { i++; }
        }
        return i == cs.len;
    }
    return false;
}

// Whether controls are well formed: Control SEQUENCEs of an OID, maybe a
// criticality, maybe a value.
fn controls_ok(buf: const u8[:], t: asn1::Tlv) -> bool {
    let cs, ok = asn1::children(buf, t, true);
    if !ok { return false; }
    for c in cs {
        let parts, okp = asn1::children(buf, c, true);
        if !okp || c.tag != asn1::SEQUENCE || parts.len < 1 || parts.len > 3 || !octets_ok(parts[0]) { return false; }
        var i = 1;
        if i < parts.len && parts[i].tag == asn1::BOOLEAN {
            let v, okb = asn1::read_bool(buf, parts[i], true);
            if !okb { return false; }
            i++;
        }
        if i < parts.len && octets_ok(parts[i]) { i++; }
        if i != parts.len { return false; }
    }
    return true;
}

// How long the LDAPMessage at the start of buf is: 0 when more bytes are
// needed, -1 when it cannot be one, or longer than max.
fn frame_len(buf: const u8[:], max: i64) -> i64 {
    if buf.len < 2 { return 0; }
    if buf[0] != 0x30 { return -1; }
    let l0 = buf[1];
    if l0 < 0x80 { return if 2 + l0 > max { -1 } else if buf.len < 2 + l0 { 0 } else { 2 + l0 } }
    let nb: i64 = l0 & 0x7f;
    if nb == 0 || nb > 8 { return -1; }
    if buf.len < 2 + nb { return 0; }
    var len: i64 = 0;
    for i in nb {
        if len > max { return -1; }
        len = (len << 8) | buf[2 + i];
    }
    if len > max - 2 - nb { return -1; }
    let total = 2 + nb + len;
    return if buf.len < total { 0 } else { total };
}

// The LDAPMessage that is buf[at..end], checked whole.
fn parse_message(buf: const u8[:], at: i64, end: i64) -> Message, bool {
    let none = asn1::Tlv { tag: 0, cls: 0, constructed: false, number: 0, start: at, off: at, end: at };
    var m = Message { id: 0, op: 0, start: at, end: end, body: none, controls: none, has_controls: false };
    let t, ok = asn1::read(buf, at, end, true);
    if !ok || t.end != end || t.tag != asn1::SEQUENCE { return m, false; }
    let cs, okc = asn1::children(buf, t, true);
    if !okc || cs.len < 2 || cs.len > 3 { return m, false; }
    let id, oki = asn1::read_i64(buf, cs[0], asn1::INTEGER, true);
    if !oki || id < 0 || id > 0x7fffffff { return m, false; }
    m.id = id;
    m.op = cs[1].tag;
    m.body = cs[1];
    if cs[1].cls != asn1::CLASS_APPLICATION || !body_ok(buf, m.op, cs[1]) { return m, false; }
    if cs.len == 3 {
        if cs[2].tag != ctx_cons(0) || !controls_ok(buf, cs[2]) { return m, false; }
        m.controls = cs[2];
        m.has_controls = true;
    }
    return m, true;
}

// The messages of a builder ldap.conn's feed appended to, one at a time.
fn next_message(msgs: const u8[:], pos: i64&) -> Message, bool {
    let n = frame_len(msgs[pos..], msgs.len);
    if n <= 0 {
        let none, x = parse_message(msgs, pos, pos);
        return none, false;
    }
    let m, ok = parse_message(msgs, pos, pos + n);
    pos = pos + n;
    return m, ok;
}

// An LDAPResult: the code, the matched DN, the diagnostic message, and
// the referral URLs if any.
struct Result { code: i64, matched: asn1::Tlv, message: asn1::Tlv, referral: asn1::Tlv, has_referral: bool }

// The result of a response (any but an entry, a reference or an
// intermediate response).
fn result(buf: const u8[:], m: const Message&) -> Result, bool {
    let cs, ok = asn1::children(buf, m.body, true);
    var r = Result { code: -1, matched: m.body, message: m.body, referral: m.body, has_referral: false };
    if !ok || !result_ok(buf, cs) { return r, false; }
    let code, okc = asn1::read_i64(buf, cs[0], asn1::ENUMERATED, true);
    r.code = code;
    r.matched = cs[1];
    r.message = cs[2];
    if cs.len > 3 && cs[3].tag == ctx_cons(3) { r.referral = cs[3]; r.has_referral = true; }
    return r, true;
}

fn result_code(buf: const u8[:], m: const Message&) -> i64 {
    let r, ok = result(buf, m);
    return r.code;
}

// The diagnostic message.
fn result_message(buf: const u8[:], m: const Message&) -> const u8[:] {
    let r, ok = result(buf, m);
    return if ok { bytes(buf, r.message) } else { "" };
}

fn matched_dn(buf: const u8[:], m: const Message&) -> const u8[:] {
    let r, ok = result(buf, m);
    return if ok { bytes(buf, r.matched) } else { "" };
}

// The response's error as go-ldap reports it, "" for success (and for
// compareTrue and compareFalse, which are answers).
fn result_error(buf: const u8[:], m: const Message&) -> u8[>..] {
    let r, ok = result(buf, m);
    if !ok { return error_text(ERROR_NETWORK, "Invalid packet format"); }
    if r.code == RESULT_SUCCESS || (m.op == OP_COMPARE_RESPONSE && (r.code == RESULT_COMPARE_TRUE || r.code == RESULT_COMPARE_FALSE)) {
        var none: u8[>..] = [];
        return none;
    }
    return error_text(r.code, bytes(buf, r.message));
}

// URLs: a result's referral, or a SearchResultReference's.
fn referrals(buf: const u8[:], m: const Message&) -> const u8[:][>..] {
    var out: const u8[:][>..] = [];
    var t = m.body;
    if m.op != OP_SEARCH_REFERENCE {
        let r, ok = result(buf, m);
        if !ok || !r.has_referral { return out; }
        t = r.referral;
    }
    let urls, ok = asn1::children(buf, t, true);
    for u in urls { out.push(bytes(buf, u)); }
    return out;
}

// A child of a response past its LDAPResult, by tag.
fn after_result(buf: const u8[:], m: const Message&, tag: u32) -> asn1::Tlv, bool {
    let cs, ok = asn1::children(buf, m.body, true);
    if ok {
        for i in 3..cs.len { if cs[i].tag == tag { return cs[i], true; } }
    }
    return m.body, false;
}

// A BindResponse's serverSaslCreds.
fn server_sasl_creds(buf: const u8[:], m: const Message&) -> const u8[:], bool {
    if m.op != OP_BIND_RESPONSE { return "", false; }
    let t, ok = after_result(buf, m, ctx_prim(7));
    return if ok { bytes(buf, t) } else { "" }, ok;
}

// An ExtendedResponse's (or an IntermediateResponse's) name and value.
fn response_name(buf: const u8[:], m: const Message&) -> const u8[:], bool {
    if m.op == OP_INTERMEDIATE {
        let cs, ok = asn1::children(buf, m.body, true);
        if ok && cs.len > 0 && cs[0].tag == ctx_prim(0) { return bytes(buf, cs[0]), true; }
        return "", false;
    }
    if m.op != OP_EXTENDED_RESPONSE { return "", false; }
    let t, ok = after_result(buf, m, ctx_prim(10));
    return if ok { bytes(buf, t) } else { "" }, ok;
}

fn response_value_tlv(buf: const u8[:], m: const Message&) -> asn1::Tlv, bool {
    if m.op == OP_INTERMEDIATE {
        let cs, ok = asn1::children(buf, m.body, true);
        if ok {
            for c in cs { if c.tag == ctx_prim(1) { return c, true; } }
        }
        return m.body, false;
    }
    if m.op != OP_EXTENDED_RESPONSE { return m.body, false; }
    return after_result(buf, m, ctx_prim(11));
}

fn response_value(buf: const u8[:], m: const Message&) -> const u8[:], bool {
    let t, ok = response_value_tlv(buf, m);
    return if ok { bytes(buf, t) } else { "" }, ok;
}

// The new password the server made up for a Password Modify request
// without one (RFC 3062's genPasswd [0]).
fn generated_password(buf: const u8[:], m: const Message&) -> const u8[:], bool {
    let v, ok = response_value_tlv(buf, m);
    if !ok { return "", false; }
    let t, okt = asn1::read(buf, v.off, v.end, true);
    if !okt || t.end != v.end || t.tag != asn1::SEQUENCE { return "", false; }
    let cs, okc = asn1::children(buf, t, true);
    if !okc || cs.len != 1 || cs[0].tag != ctx_prim(0) { return "", false; }
    return bytes(buf, cs[0]), true;
}

// --- Entries ----------------------------------------------------------------------

// A SearchResultEntry's attribute: its description and SET of values.
struct Attribute { name: asn1::Tlv, values: asn1::Tlv }

fn entry_dn(buf: const u8[:], m: const Message&) -> const u8[:] {
    let cs, ok = asn1::children(buf, m.body, true);
    return if ok && m.op == OP_SEARCH_ENTRY { bytes(buf, cs[0]) } else { "" };
}

fn attributes(buf: const u8[:], m: const Message&) -> Attribute[>..] {
    var out: Attribute[>..] = [];
    if m.op != OP_SEARCH_ENTRY { return out; }
    let cs, ok = asn1::children(buf, m.body, true);
    if !ok { return out; }
    let attrs, oka = asn1::children(buf, cs[1], true);
    for a in attrs {
        let parts, okp = asn1::children(buf, a, true);
        out.push(Attribute { name: parts[0], values: parts[1] });
    }
    return out;
}

fn attribute_name(buf: const u8[:], a: Attribute) -> const u8[:] { bytes(buf, a.name) }

fn attribute_values(buf: const u8[:], a: Attribute) -> const u8[:][>..] {
    var out: const u8[:][>..] = [];
    let vals, ok = asn1::children(buf, a.values, true);
    for v in vals { out.push(bytes(buf, v)); }
    return out;
}

// A hex digit's value, -1 for none.
fn hex_value(c: u8) -> i64 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'a' && c <= 'f' { return c - 'a' + 10; }
    if c >= 'A' && c <= 'F' { return c - 'A' + 10; }
    return -1;
}

fn lower(c: u8) -> u8 { if c >= 'A' && c <= 'Z' { c + 32 } else { c } }

// ASCII case-insensitive equality, as attribute descriptions compare.
fn equal_fold(a: const u8[:], b: const u8[:]) -> bool {
    if a.len != b.len { return false; }
    for i in a.len { if lower(a[i]) != lower(b[i]) { return false; } }
    return true;
}

// The values of an entry's attribute, the name matched without regard to
// case (go-ldap's GetEqualFoldRawAttributeValues).
fn get_values(buf: const u8[:], m: const Message&, name: const u8[:]) -> const u8[:][>..] {
    for a in attributes(buf, m) {
        if equal_fold(attribute_name(buf, a), name) { return attribute_values(buf, a); }
    }
    var none: const u8[:][>..] = [];
    return none;
}

// Its first value, or "".
fn get_value(buf: const u8[:], m: const Message&, name: const u8[:]) -> const u8[:] {
    for a in attributes(buf, m) {
        if equal_fold(attribute_name(buf, a), name) {
            let vals, ok = asn1::children(buf, a.values, true);
            for v in vals { return bytes(buf, v); }
        }
    }
    return "";
}

// --- Controls of a response ------------------------------------------------------------

struct Control { oid: asn1::Tlv, critical: bool, value: asn1::Tlv, has_value: bool }

fn controls(buf: const u8[:], m: const Message&) -> Control[>..] {
    var out: Control[>..] = [];
    if !m.has_controls { return out; }
    let cs, ok = asn1::children(buf, m.controls, true);
    for c in cs {
        let parts, okp = asn1::children(buf, c, true);
        var k = Control { oid: parts[0], critical: false, value: parts[0], has_value: false };
        var i = 1;
        if i < parts.len && parts[i].tag == asn1::BOOLEAN {
            let v, okb = asn1::read_bool(buf, parts[i], true);
            k.critical = v;
            i++;
        }
        if i < parts.len { k.value = parts[i]; k.has_value = true; }
        out.push(k);
    }
    return out;
}

fn find_control(buf: const u8[:], m: const Message&, oid: const u8[:]) -> Control, bool {
    for c in controls(buf, m) {
        if bytes(buf, c.oid) == oid { return c, true; }
    }
    let none = Control { oid: m.body, critical: false, value: m.body, has_value: false };
    return none, false;
}

// The element inside a control's value, read as BER.
fn control_inner(buf: const u8[:], c: Control) -> asn1::Tlv, bool {
    if !c.has_value { return c.value, false; }
    let t, ok = asn1::read(buf, c.value.off, c.value.end, true);
    return t, ok && t.end == c.value.end;
}

// The paging response (RFC 2696): the server's estimate of the size and
// the cookie for the next page ("" when this was the last).
fn paging(buf: const u8[:], c: Control) -> i64, const u8[:], bool {
    let t, ok = control_inner(buf, c);
    if !ok || t.tag != asn1::SEQUENCE { return 0, "", false; }
    let cs, okc = asn1::children(buf, t, true);
    if !okc || cs.len != 2 || !octets_ok(cs[1]) { return 0, "", false; }
    let size, oks = asn1::read_i64(buf, cs[0], asn1::INTEGER, true);
    return size, bytes(buf, cs[1]), oks;
}

// The paging cookie of a SearchResultDone, "" for none or the last page.
fn paging_cookie(buf: const u8[:], m: const Message&) -> const u8[:] {
    let c, ok = find_control(buf, m, CONTROL_PAGING);
    if !ok { return ""; }
    let size, cookie, okp = paging(buf, c);
    return if okp { cookie } else { "" };
}

// The Behera password policy response: seconds before expiration (-1),
// grace logins left (-1), the error (-1 for none), as go-ldap decodes it.
fn ppolicy(buf: const u8[:], c: Control) -> i64, i64, i64, bool {
    var expire: i64 = -1;
    var grace: i64 = -1;
    var err: i64 = -1;
    let t, ok = control_inner(buf, c);
    if !ok || t.tag != asn1::SEQUENCE { return expire, grace, err, false; }
    let cs, okc = asn1::children(buf, t, true);
    if !okc { return expire, grace, err, false; }
    for x in cs {
        if x.tag == ctx_cons(0) {
            let w, okw = asn1::explicit(buf, x, true);
            if !okw { return expire, grace, err, false; }
            // The choice is [0] or [1] over an INTEGER, IMPLICIT.
            let tmp_tag = w.tag;
            if tmp_tag != ctx_prim(0) && tmp_tag != ctx_prim(1) { return expire, grace, err, false; }
            let v, okv = asn1::read_i64(buf, w, tmp_tag, true);
            if !okv { return expire, grace, err, false; }
            if tmp_tag == ctx_prim(0) { expire = v; } else { grace = v; }
        } else if x.tag == ctx_prim(1) {
            if asn1::content_len(x) != 1 || buf[x.off] > 8 { return expire, grace, err, false; }
            err = buf[x.off];
        } else {
            return expire, grace, err, false;
        }
    }
    return expire, grace, err, true;
}

// The VChu password warning: seconds before the password expires.
fn vchu_warning(buf: const u8[:], c: Control) -> i64, bool {
    if !c.has_value { return -1, false; }
    let v, ok = parse_int(bytes(buf, c.value), 10);
    return if ok { v } else { -1 }, ok;
}

// The sort response (RFC 2891): the result code, and the attribute that
// caused a failure ("" for none).
fn sort_result(buf: const u8[:], c: Control) -> i64, const u8[:], bool {
    let t, ok = control_inner(buf, c);
    if !ok || t.tag != asn1::SEQUENCE { return -1, "", false; }
    let cs, okc = asn1::children(buf, t, true);
    if !okc || cs.len < 1 || cs.len > 2 { return -1, "", false; }
    let code, okr = asn1::read_i64(buf, cs[0], asn1::ENUMERATED, true);
    if cs.len == 2 {
        if cs[1].tag != ctx_prim(0) { return -1, "", false; }
        return code, bytes(buf, cs[1]), okr;
    }
    return code, "", okr;
}
