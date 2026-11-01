// krb5.sys: the C that krb5 calls (krb5/src/krb5sys.c, and http's TCP
// sockets in net/http/src/httpnet.c). Results >= 0 are successes; the
// negative ones are SYS_E*.

namespace krb5;

extern fn httpnet_connect(host: const u8[:], port: i32, timeout_ms: i32) -> i64;
extern fn httpnet_read(fd: i64, buf: u8[:], timeout_ms: i32) -> i64;
extern fn httpnet_write(fd: i64, data: const u8[:], timeout_ms: i32) -> i64;
extern fn httpnet_close(fd: i64);

extern fn krb5sys_udp_exchange(host: const u8[:], port: i32, req: const u8[:], out: u8[:], timeout_ms: i32) -> i64;
extern fn krb5sys_write_private(path: const u8[:], data: const u8[:]) -> i32;
extern fn krb5sys_uid() -> i64;
extern fn krb5sys_hostname(out: u8[:]) -> i64;
extern fn krb5sys_canonical_host(host: const u8[:], out: u8[:]) -> i64;

let SYS_EARG: i64 = -1;
let SYS_ERESOLVE: i64 = -2;
let SYS_ECONNECT: i64 = -3;
let SYS_ETIMEOUT: i64 = -4;
let SYS_EIO: i64 = -5;
