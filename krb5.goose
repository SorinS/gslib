// krb5: Kerberos V5 (RFC 4120), as go-krb5 (github.com/go-krb5/krb5) has
// it, with its GSS-API mechanism (RFC 4121), SPNEGO (RFC 4178) and
// Microsoft's PAC (MS-PAC). This module holds the protocol's numbers and
// error codes, which every other module shares.
//
//   krb5.crypto     the encryption types (RFC 3961, 3962, 4757, 8009)
//   krb5.messages   the ASN.1 messages (RFC 4120 §5), encoded and read
//   krb5.keytab     MIT keytab files
//   krb5.ccache     MIT credential caches (FILE: formats 3 and 4)
//   krb5.config     krb5.conf
//   krb5.client     AS and TGS exchanges: TGTs, service tickets, referrals
//   krb5.service    the acceptor: AP-REQ checks, replay cache
//   krb5.gssapi     RFC 4121 tokens: context establishment, MIC, Wrap
//   krb5.spnego     RFC 4178 negotiation tokens, HTTP Negotiate (RFC 4559)
//   krb5.ndr        NDR (MS-RPCE) decoding, for the PAC
//   krb5.pac        the PAC: logon info, UPN/DNS info, signatures
//   krb5.claims     the PAC's claims, and MS-XCA decompression
//   krb5.net        talking to KDCs over UDP and TCP
//   krb5.ldap       SASL GSSAPI binds (RFC 4752) and SID lookups in AD
//   krb5.sys        the C it calls (src/krb5sys.c, http's TCP sockets)
//
// Nothing here does I/O but krb5.net, the file functions (keytabs,
// caches, krb5.conf) and the tools; krb5.ldap writes and reads bytes for
// the caller's connection.

namespace krb5;

import std;

// --- Encryption types (IANA) ------------------------------------------------

let ETYPE_DES3_CBC_SHA1_KD: i32 = 16;
let ETYPE_AES128_CTS_HMAC_SHA1_96: i32 = 17;
let ETYPE_AES256_CTS_HMAC_SHA1_96: i32 = 18;
let ETYPE_AES128_CTS_HMAC_SHA256_128: i32 = 19;
let ETYPE_AES256_CTS_HMAC_SHA384_192: i32 = 20;
let ETYPE_RC4_HMAC: i32 = 23;
let ETYPE_CAMELLIA128_CTS_CMAC: i32 = 25;
let ETYPE_CAMELLIA256_CTS_CMAC: i32 = 26;

// --- Checksum types ---------------------------------------------------------

let CKSUM_RSA_MD5: i32 = 7;
let CKSUM_HMAC_SHA1_DES3_KD: i32 = 12;
let CKSUM_SHA1: i32 = 14;
let CKSUM_HMAC_SHA1_96_AES128: i32 = 15;
let CKSUM_HMAC_SHA1_96_AES256: i32 = 16;
let CKSUM_CMAC_CAMELLIA128: i32 = 17;
let CKSUM_CMAC_CAMELLIA256: i32 = 18;
let CKSUM_HMAC_SHA256_128_AES128: i32 = 19;
let CKSUM_HMAC_SHA384_192_AES256: i32 = 20;
let CKSUM_GSSAPI: i32 = 0x8003;
let CKSUM_HMAC_MD5: i32 = -138;

// --- Key usages (RFC 4120 §7.5.1, RFC 4121 §2, MS-PAC) ----------------------

let USAGE_AS_REQ_PA_ENC_TIMESTAMP: i64 = 1;
let USAGE_KDC_REP_TICKET: i64 = 2;
let USAGE_AS_REP_ENCPART: i64 = 3;
let USAGE_TGS_REQ_AUTHDATA_SESSION_KEY: i64 = 4;
let USAGE_TGS_REQ_AUTHDATA_SUBKEY: i64 = 5;
let USAGE_TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR_CKSUM: i64 = 6;
let USAGE_TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR: i64 = 7;
let USAGE_TGS_REP_ENCPART_SESSION_KEY: i64 = 8;
let USAGE_TGS_REP_ENCPART_SUBKEY: i64 = 9;
let USAGE_AP_REQ_AUTHENTICATOR_CKSUM: i64 = 10;
let USAGE_AP_REQ_AUTHENTICATOR: i64 = 11;
let USAGE_AP_REP_ENCPART: i64 = 12;
let USAGE_KRB_PRIV_ENCPART: i64 = 13;
let USAGE_KRB_CRED_ENCPART: i64 = 14;
let USAGE_KRB_SAFE_CKSUM: i64 = 15;
let USAGE_KERB_NON_KERB_SALT: i64 = 16;
let USAGE_KERB_NON_KERB_CKSUM_SALT: i64 = 17;
let USAGE_GSSAPI_ACCEPTOR_SEAL: i64 = 22;
let USAGE_GSSAPI_ACCEPTOR_SIGN: i64 = 23;
let USAGE_GSSAPI_INITIATOR_SEAL: i64 = 24;
let USAGE_GSSAPI_INITIATOR_SIGN: i64 = 25;
// FAST (RFC 6113 §5.4), and the request's checksum in an AS-REP (RFC 6806 §11).
let USAGE_FAST_REQ_CHKSUM: i64 = 50;
let USAGE_FAST_ENC: i64 = 51;
let USAGE_FAST_REP: i64 = 52;
let USAGE_FAST_FINISHED: i64 = 53;
let USAGE_ENC_CHALLENGE_CLIENT: i64 = 54;
let USAGE_ENC_CHALLENGE_KDC: i64 = 55;
let USAGE_AS_REQ: i64 = 56;

// --- Message types and their APPLICATION tags (RFC 4120 §5.10) --------------

let MSG_AS_REQ: i64 = 10;
let MSG_AS_REP: i64 = 11;
let MSG_TGS_REQ: i64 = 12;
let MSG_TGS_REP: i64 = 13;
let MSG_AP_REQ: i64 = 14;
let MSG_AP_REP: i64 = 15;
let MSG_KRB_SAFE: i64 = 20;
let MSG_KRB_PRIV: i64 = 21;
let MSG_KRB_CRED: i64 = 22;
let MSG_KRB_ERROR: i64 = 30;

let APP_TICKET: u32 = 1;
let APP_AUTHENTICATOR: u32 = 2;
let APP_ENC_TICKET_PART: u32 = 3;
let APP_AS_REQ: u32 = 10;
let APP_AS_REP: u32 = 11;
let APP_TGS_REQ: u32 = 12;
let APP_TGS_REP: u32 = 13;
let APP_AP_REQ: u32 = 14;
let APP_AP_REP: u32 = 15;
let APP_KRB_SAFE: u32 = 20;
let APP_KRB_PRIV: u32 = 21;
let APP_KRB_CRED: u32 = 22;
let APP_ENC_AS_REP_PART: u32 = 25;
let APP_ENC_TGS_REP_PART: u32 = 26;
let APP_ENC_AP_REP_PART: u32 = 27;
let APP_ENC_KRB_PRIV_PART: u32 = 28;
let APP_ENC_KRB_CRED_PART: u32 = 29;
let APP_KRB_ERROR: u32 = 30;

// The identifier octet of [APPLICATION n] (constructed), n < 31.
fn app(n: u32) -> u32 { 0x60 | n }

// --- Principal name types (RFC 4120 §6.2, MS-KILE) --------------------------

let NT_UNKNOWN: i32 = 0;
let NT_PRINCIPAL: i32 = 1;
let NT_SRV_INST: i32 = 2;
let NT_SRV_HST: i32 = 3;
let NT_SRV_XHST: i32 = 4;
let NT_UID: i32 = 5;
let NT_X500_PRINCIPAL: i32 = 6;
let NT_SMTP_NAME: i32 = 7;
let NT_ENTERPRISE: i32 = 10;
let NT_WELLKNOWN: i32 = 11;
let NT_SRV_HST_DOMAIN: i32 = 12;
let NT_MS_PRINCIPAL: i32 = -128;
let NT_MS_PRINCIPAL_AND_ID: i32 = -129;
let NT_ENT_PRINCIPAL_AND_ID: i32 = -130;

// --- Pre-authentication data types ------------------------------------------

let PA_TGS_REQ: i32 = 1;
let PA_ENC_TIMESTAMP: i32 = 2;
let PA_PW_SALT: i32 = 3;
let PA_ETYPE_INFO: i32 = 11;
let PA_PK_AS_REQ: i32 = 16;
let PA_PK_AS_REP: i32 = 17;
let PA_ETYPE_INFO2: i32 = 19;
let PA_SVR_REFERRAL_INFO: i32 = 20;
let PA_PAC_REQUEST: i32 = 128;
let PA_FOR_USER: i32 = 129;
let PA_FX_COOKIE: i32 = 133;
let PA_FX_FAST: i32 = 136;
let PA_FX_ERROR: i32 = 137;
let PA_ENCRYPTED_CHALLENGE: i32 = 138;
let PA_REQ_ENC_PA_REP: i32 = 149;
let PA_SUPPORTED_ENCTYPES: i32 = 165;
let PA_PAC_OPTIONS: i32 = 167;

// FAST armor types and options (RFC 6113 §5.4.1, §5.4.2).
let FX_FAST_ARMOR_AP_REQUEST: i32 = 1;
let FAST_OPT_HIDE_CLIENT_NAMES: i64 = 1;
let FAST_OPT_KDC_FOLLOW_REFERRALS: i64 = 16;

// --- Authorization data types -----------------------------------------------

let AD_IF_RELEVANT: i32 = 1;
let AD_INTENDED_FOR_SERVER: i32 = 2;
let AD_KDC_ISSUED: i32 = 4;
let AD_AND_OR: i32 = 5;
let AD_MANDATORY_FOR_KDC: i32 = 8;
let AD_WIN2K_PAC: i32 = 128;
let AD_ETYPE_NEGOTIATION: i32 = 129;
let AD_TOKEN_RESTRICTIONS: i32 = 141;
let AD_LOCAL: i32 = 142;
let AD_AP_OPTIONS: i32 = 143;

// --- Flags ------------------------------------------------------------------
//
// KerberosFlags (§5.2.8) as a u32: bit n of the BIT STRING, numbered from
// the first octet's high bit, is 1 << (31 - n). flag(n) gives that mask.

fn flag(n: i64) -> u32 { (1 as u32) << ((31 - n) as! u32) }

// KDCOptions (§5.4.1)
let KDC_OPT_FORWARDABLE: i64 = 1;
let KDC_OPT_FORWARDED: i64 = 2;
let KDC_OPT_PROXIABLE: i64 = 3;
let KDC_OPT_PROXY: i64 = 4;
let KDC_OPT_ALLOW_POSTDATE: i64 = 5;
let KDC_OPT_POSTDATED: i64 = 6;
let KDC_OPT_RENEWABLE: i64 = 8;
let KDC_OPT_CNAME_IN_ADDL_TKT: i64 = 14;
let KDC_OPT_CANONICALIZE: i64 = 15;
let KDC_OPT_REQUEST_ANONYMOUS: i64 = 16;
let KDC_OPT_DISABLE_TRANSITED_CHECK: i64 = 26;
let KDC_OPT_RENEWABLE_OK: i64 = 27;
let KDC_OPT_ENC_TKT_IN_SKEY: i64 = 28;
let KDC_OPT_RENEW: i64 = 30;
let KDC_OPT_VALIDATE: i64 = 31;

// TicketFlags (§5.3)
let TKT_FORWARDABLE: i64 = 1;
let TKT_FORWARDED: i64 = 2;
let TKT_PROXIABLE: i64 = 3;
let TKT_PROXY: i64 = 4;
let TKT_MAY_POSTDATE: i64 = 5;
let TKT_POSTDATED: i64 = 6;
let TKT_INVALID: i64 = 7;
let TKT_RENEWABLE: i64 = 8;
let TKT_INITIAL: i64 = 9;
let TKT_PRE_AUTHENT: i64 = 10;
let TKT_HW_AUTHENT: i64 = 11;
let TKT_TRANSITED_POLICY_CHECKED: i64 = 12;
let TKT_OK_AS_DELEGATE: i64 = 13;
let TKT_ENC_PA_REP: i64 = 15;
let TKT_ANONYMOUS: i64 = 16;

// APOptions (§5.5.1)
let AP_OPT_USE_SESSION_KEY: i64 = 1;
let AP_OPT_MUTUAL_REQUIRED: i64 = 2;

// --- Errors -----------------------------------------------------------------
//
// Every fallible function returns an error code, 0 for success. Codes 0 to
// 99 are the protocol's (RFC 4120 §7.5.9, a KRB-ERROR's error-code); the
// library's own start at 1000. error_text names either kind.

let OK: i64 = 0;

let KDC_ERR_NAME_EXP: i64 = 1;
let KDC_ERR_SERVICE_EXP: i64 = 2;
let KDC_ERR_BAD_PVNO: i64 = 3;
let KDC_ERR_C_OLD_MAST_KVNO: i64 = 4;
let KDC_ERR_S_OLD_MAST_KVNO: i64 = 5;
let KDC_ERR_C_PRINCIPAL_UNKNOWN: i64 = 6;
let KDC_ERR_S_PRINCIPAL_UNKNOWN: i64 = 7;
let KDC_ERR_PRINCIPAL_NOT_UNIQUE: i64 = 8;
let KDC_ERR_NULL_KEY: i64 = 9;
let KDC_ERR_CANNOT_POSTDATE: i64 = 10;
let KDC_ERR_NEVER_VALID: i64 = 11;
let KDC_ERR_POLICY: i64 = 12;
let KDC_ERR_BADOPTION: i64 = 13;
let KDC_ERR_ETYPE_NOSUPP: i64 = 14;
let KDC_ERR_SUMTYPE_NOSUPP: i64 = 15;
let KDC_ERR_PADATA_TYPE_NOSUPP: i64 = 16;
let KDC_ERR_TRTYPE_NOSUPP: i64 = 17;
let KDC_ERR_CLIENT_REVOKED: i64 = 18;
let KDC_ERR_SERVICE_REVOKED: i64 = 19;
let KDC_ERR_TGT_REVOKED: i64 = 20;
let KDC_ERR_CLIENT_NOTYET: i64 = 21;
let KDC_ERR_SERVICE_NOTYET: i64 = 22;
let KDC_ERR_KEY_EXPIRED: i64 = 23;
let KDC_ERR_PREAUTH_FAILED: i64 = 24;
let KDC_ERR_PREAUTH_REQUIRED: i64 = 25;
let KDC_ERR_SERVER_NOMATCH: i64 = 26;
let KDC_ERR_MUST_USE_USER2USER: i64 = 27;
let KDC_ERR_PATH_NOT_ACCEPTED: i64 = 28;
let KDC_ERR_SVC_UNAVAILABLE: i64 = 29;
let KRB_AP_ERR_BAD_INTEGRITY: i64 = 31;
let KRB_AP_ERR_TKT_EXPIRED: i64 = 32;
let KRB_AP_ERR_TKT_NYV: i64 = 33;
let KRB_AP_ERR_REPEAT: i64 = 34;
let KRB_AP_ERR_NOT_US: i64 = 35;
let KRB_AP_ERR_BADMATCH: i64 = 36;
let KRB_AP_ERR_SKEW: i64 = 37;
let KRB_AP_ERR_BADADDR: i64 = 38;
let KRB_AP_ERR_BADVERSION: i64 = 39;
let KRB_AP_ERR_MSG_TYPE: i64 = 40;
let KRB_AP_ERR_MODIFIED: i64 = 41;
let KRB_AP_ERR_BADORDER: i64 = 42;
let KRB_AP_ERR_BADKEYVER: i64 = 44;
let KRB_AP_ERR_NOKEY: i64 = 45;
let KRB_AP_ERR_MUT_FAIL: i64 = 46;
let KRB_AP_ERR_BADDIRECTION: i64 = 47;
let KRB_AP_ERR_METHOD: i64 = 48;
let KRB_AP_ERR_BADSEQ: i64 = 49;
let KRB_AP_ERR_INAPP_CKSUM: i64 = 50;
let KRB_AP_PATH_NOT_ACCEPTED: i64 = 51;
let KRB_ERR_RESPONSE_TOO_BIG: i64 = 52;
let KRB_ERR_GENERIC: i64 = 60;
let KRB_ERR_FIELD_TOOLONG: i64 = 61;
let KDC_ERR_CLIENT_NOT_TRUSTED: i64 = 62;
let KDC_ERR_KDC_NOT_TRUSTED: i64 = 63;
let KDC_ERR_INVALID_SIG: i64 = 64;
let KDC_ERR_KEY_TOO_WEAK: i64 = 65;
let KDC_ERR_CERTIFICATE_MISMATCH: i64 = 66;
let KRB_AP_ERR_NO_TGT: i64 = 67;
let KDC_ERR_WRONG_REALM: i64 = 68;
let KRB_AP_ERR_USER_TO_USER_REQUIRED: i64 = 69;
let KDC_ERR_CANT_VERIFY_CERTIFICATE: i64 = 70;
let KDC_ERR_INVALID_CERTIFICATE: i64 = 71;
let KDC_ERR_REVOKED_CERTIFICATE: i64 = 72;
let KDC_ERR_REVOCATION_STATUS_UNKNOWN: i64 = 73;
let KDC_ERR_REVOCATION_STATUS_UNAVAILABLE: i64 = 74;
let KDC_ERR_CLIENT_NAME_MISMATCH: i64 = 75;
let KDC_ERR_KDC_NAME_MISMATCH: i64 = 76;
let KDC_ERR_PREAUTH_EXPIRED: i64 = 90;
let KDC_ERR_MORE_PREAUTH_DATA_REQUIRED: i64 = 91;
let KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS: i64 = 93;

// The library's own.
let ERR_MALFORMED: i64 = 1000;         // a message that does not parse
let ERR_UNEXPECTED: i64 = 1001;        // a message of the wrong type or tag
let ERR_ETYPE: i64 = 1002;             // an encryption type we do not have
let ERR_CKSUMTYPE: i64 = 1003;         // a checksum type we do not have
let ERR_KEY_SIZE: i64 = 1004;          // a key of the wrong length for its type
let ERR_INTEGRITY: i64 = 1005;         // a ciphertext or checksum that fails its check
let ERR_CIPHERTEXT: i64 = 1006;        // a ciphertext too short for its type
let ERR_S2K_PARAMS: i64 = 1007;        // string-to-key parameters out of range
let ERR_NONCE: i64 = 1008;             // a KDC reply's nonce differs from the request's
let ERR_NAME_MISMATCH: i64 = 1009;     // a reply for another client or service
let ERR_NO_KEY: i64 = 1010;            // no key for the name, type or version
let ERR_NO_CREDS: i64 = 1011;          // no credentials for the name
let ERR_KDC_UNREACHABLE: i64 = 1012;   // no KDC answered
let ERR_NO_KDC: i64 = 1013;            // no KDC configured for the realm
let ERR_FILE: i64 = 1014;              // a file that cannot be read or written
let ERR_FORMAT: i64 = 1015;            // a keytab or cache in a format we do not read
let ERR_CONFIG: i64 = 1016;            // a krb5.conf that does not parse
let ERR_REFERRALS: i64 = 1017;         // referrals that loop or run too long
let ERR_NAME: i64 = 1018;              // a principal name that does not parse
let ERR_TOKEN: i64 = 1019;             // a GSS-API or SPNEGO token that does not parse
let ERR_MECH: i64 = 1020;              // SPNEGO without a mechanism we have
let ERR_SEQUENCE: i64 = 1021;          // a GSS-API token out of sequence
let ERR_PAC: i64 = 1022;               // a PAC that does not parse
let ERR_PAC_SIGNATURE: i64 = 1023;     // a PAC whose signature fails
let ERR_NDR: i64 = 1024;               // NDR that does not decode
let ERR_PREAUTH: i64 = 1025;           // pre-authentication we cannot do
let ERR_TIME: i64 = 1026;              // a time out of range
let ERR_CONTEXT: i64 = 1027;           // a GSS-API context used in the wrong state
let ERR_FAST: i64 = 1028;              // a KDC reply not armored as FAST requires, or altered

fn error_text(code: i64) -> const u8[:] {
    match code {
        0 => "OK",
        1 => "KDC_ERR_NAME_EXP Client's entry in database has expired",
        2 => "KDC_ERR_SERVICE_EXP Server's entry in database has expired",
        3 => "KDC_ERR_BAD_PVNO Requested protocol version number not supported",
        4 => "KDC_ERR_C_OLD_MAST_KVNO Client's key encrypted in old master key",
        5 => "KDC_ERR_S_OLD_MAST_KVNO Server's key encrypted in old master key",
        6 => "KDC_ERR_C_PRINCIPAL_UNKNOWN Client not found in Kerberos database",
        7 => "KDC_ERR_S_PRINCIPAL_UNKNOWN Server not found in Kerberos database",
        8 => "KDC_ERR_PRINCIPAL_NOT_UNIQUE Multiple principal entries in database",
        9 => "KDC_ERR_NULL_KEY The client or server has a null key",
        10 => "KDC_ERR_CANNOT_POSTDATE Ticket not eligible for postdating",
        11 => "KDC_ERR_NEVER_VALID Requested starttime is later than end time",
        12 => "KDC_ERR_POLICY KDC policy rejects request",
        13 => "KDC_ERR_BADOPTION KDC cannot accommodate requested option",
        14 => "KDC_ERR_ETYPE_NOSUPP KDC has no support for encryption type",
        15 => "KDC_ERR_SUMTYPE_NOSUPP KDC has no support for checksum type",
        16 => "KDC_ERR_PADATA_TYPE_NOSUPP KDC has no support for padata type",
        17 => "KDC_ERR_TRTYPE_NOSUPP KDC has no support for transited type",
        18 => "KDC_ERR_CLIENT_REVOKED Clients credentials have been revoked",
        19 => "KDC_ERR_SERVICE_REVOKED Credentials for server have been revoked",
        20 => "KDC_ERR_TGT_REVOKED TGT has been revoked",
        21 => "KDC_ERR_CLIENT_NOTYET Client not yet valid; try again later",
        22 => "KDC_ERR_SERVICE_NOTYET Server not yet valid; try again later",
        23 => "KDC_ERR_KEY_EXPIRED Password has expired; change password to reset",
        24 => "KDC_ERR_PREAUTH_FAILED Pre-authentication information was invalid",
        25 => "KDC_ERR_PREAUTH_REQUIRED Additional pre-authentication required",
        26 => "KDC_ERR_SERVER_NOMATCH Requested server and ticket don't match",
        27 => "KDC_ERR_MUST_USE_USER2USER Server principal valid for user2user only",
        28 => "KDC_ERR_PATH_NOT_ACCEPTED KDC Policy rejects transited path",
        29 => "KDC_ERR_SVC_UNAVAILABLE A service is not available",
        31 => "KRB_AP_ERR_BAD_INTEGRITY Integrity check on decrypted field failed",
        32 => "KRB_AP_ERR_TKT_EXPIRED Ticket expired",
        33 => "KRB_AP_ERR_TKT_NYV Ticket not yet valid",
        34 => "KRB_AP_ERR_REPEAT Request is a replay",
        35 => "KRB_AP_ERR_NOT_US The ticket isn't for us",
        36 => "KRB_AP_ERR_BADMATCH Ticket and authenticator don't match",
        37 => "KRB_AP_ERR_SKEW Clock skew too great",
        38 => "KRB_AP_ERR_BADADDR Incorrect net address",
        39 => "KRB_AP_ERR_BADVERSION Protocol version mismatch",
        40 => "KRB_AP_ERR_MSG_TYPE Invalid msg type",
        41 => "KRB_AP_ERR_MODIFIED Message stream modified",
        42 => "KRB_AP_ERR_BADORDER Message out of order",
        44 => "KRB_AP_ERR_BADKEYVER Specified version of key is not available",
        45 => "KRB_AP_ERR_NOKEY Service key not available",
        46 => "KRB_AP_ERR_MUT_FAIL Mutual authentication failed",
        47 => "KRB_AP_ERR_BADDIRECTION Incorrect message direction",
        48 => "KRB_AP_ERR_METHOD Alternative authentication method required",
        49 => "KRB_AP_ERR_BADSEQ Incorrect sequence number in message",
        50 => "KRB_AP_ERR_INAPP_CKSUM Inappropriate type of checksum in message",
        51 => "KRB_AP_PATH_NOT_ACCEPTED Policy rejects transited path",
        52 => "KRB_ERR_RESPONSE_TOO_BIG Response too big for UDP; retry with TCP",
        60 => "KRB_ERR_GENERIC Generic error (description in e-text)",
        61 => "KRB_ERR_FIELD_TOOLONG Field is too long for this implementation",
        62 => "KDC_ERROR_CLIENT_NOT_TRUSTED Reserved for PKINIT",
        63 => "KDC_ERROR_KDC_NOT_TRUSTED Reserved for PKINIT",
        64 => "KDC_ERROR_INVALID_SIG Reserved for PKINIT",
        65 => "KDC_ERR_KEY_TOO_WEAK Reserved for PKINIT",
        66 => "KDC_ERR_CERTIFICATE_MISMATCH Reserved for PKINIT",
        67 => "KRB_AP_ERR_NO_TGT No TGT available to validate USER-TO-USER",
        68 => "KDC_ERR_WRONG_REALM Reserved for future use",
        69 => "KRB_AP_ERR_USER_TO_USER_REQUIRED Ticket must be for USER-TO-USER",
        70 => "KDC_ERR_CANT_VERIFY_CERTIFICATE Reserved for PKINIT",
        71 => "KDC_ERR_INVALID_CERTIFICATE Reserved for PKINIT",
        72 => "KDC_ERR_REVOKED_CERTIFICATE Reserved for PKINIT",
        73 => "KDC_ERR_REVOCATION_STATUS_UNKNOWN Reserved for PKINIT",
        74 => "KDC_ERR_REVOCATION_STATUS_UNAVAILABLE Reserved for PKINIT",
        75 => "KDC_ERR_CLIENT_NAME_MISMATCH Reserved for PKINIT",
        76 => "KDC_ERR_KDC_NAME_MISMATCH Reserved for PKINIT",
        90 => "KDC_ERR_PREAUTH_EXPIRED Pre-authentication has expired",
        91 => "KDC_ERR_MORE_PREAUTH_DATA_REQUIRED Additional pre-authentication data required",
        93 => "KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS Unknown critical FAST options",
        1000 => "krb5: malformed message",
        1001 => "krb5: unexpected message type",
        1002 => "krb5: unsupported encryption type",
        1003 => "krb5: unsupported checksum type",
        1004 => "krb5: wrong key size for the encryption type",
        1005 => "krb5: integrity check failed",
        1006 => "krb5: ciphertext too short",
        1007 => "krb5: string-to-key parameters out of range",
        1008 => "krb5: nonce mismatch in KDC reply",
        1009 => "krb5: KDC reply for another principal",
        1010 => "krb5: no key for the principal, encryption type or key version",
        1011 => "krb5: no credentials for the principal",
        1012 => "krb5: no KDC answered",
        1013 => "krb5: no KDC configured for the realm",
        1014 => "krb5: file cannot be read or written",
        1015 => "krb5: unsupported file format",
        1016 => "krb5: malformed krb5.conf",
        1017 => "krb5: too many referrals",
        1018 => "krb5: malformed principal name",
        1019 => "krb5: malformed GSS-API or SPNEGO token",
        1020 => "krb5: no common SPNEGO mechanism",
        1021 => "krb5: GSS-API token out of sequence",
        1022 => "krb5: malformed PAC",
        1023 => "krb5: PAC signature check failed",
        1024 => "krb5: malformed NDR",
        1025 => "krb5: unsupported pre-authentication",
        1026 => "krb5: time out of range",
        1027 => "krb5: GSS-API context in the wrong state",
        1028 => "krb5: KDC reply without the FAST armor it needs, or altered",
        _ => "krb5: unknown error",
    }
}
