// transport: SSH's transport layer piece by piece, as a connection runs
// it: the algorithms negotiated from two preference lists, a key exchange
// (the post-quantum mlkem768x25519-sha256) giving both sides the same
// secret, the exchange hash and the keys derived from it, and the binary
// packet protocol sealing and opening packets under them.
//
//   goose examples/ssh/transport.goose

import std;
import gslib from "../..";
import gslib.crypto.ssh;
import gslib.crypto.ssh.kex;
import gslib.crypto.ssh.cipher;

fn run() {
    // Negotiation: the client's first choice that the server has.
    let kex_name = ssh::negotiate("mlkem768x25519-sha256,curve25519-sha256", ssh::KEX_DEFAULT);
    let cipher = ssh::negotiate("chacha20-poly1305@openssh.com,aes256-gcm@openssh.com", ssh::CIPHERS);
    let mac = ssh::negotiate("hmac-sha2-256-etm@openssh.com", ssh::MACS);
    print("negotiated: ", kex_name, ", ", cipher, " (", mac, " unused under an AEAD)");

    // The key exchange: each side's public value goes to the other.
    var client, okc = ssh::kex_method(kex_name);
    var server, oks = ssh::kex_method(kex_name);
    guard okc && oks else { print("transport: unknown method"); exit(1); }
    ssh::kex_keygen(client);
    let k_server, ok1 = ssh::kex_server_secret(server, client.mine);   // the server answers the client's value
    let k_client, ok2 = ssh::kex_client_secret(client, server.mine);
    guard ok1 && ok2 && k_server == k_client else { print("transport: the sides disagree"); exit(1); }
    print("key exchange: client value ", client.mine.len, " bytes, server's ", server.mine.len, ", shared secret ", k_client.len);

    // The exchange hash H over both versions, both KEXINITs, the host key
    // and the values (here stand-ins for the messages), and the keys:
    // 'C' and 'D' are the client-to-server and server-to-client keys.
    let h = ssh::exchange_hash(client, "SSH-2.0-client", "SSH-2.0-server", "client kexinit", "server kexinit",
                               "host key blob", client.mine, server.mine, k_client);
    let session_id = h;                                                // the first H names the session
    let klen, ivlen, okz = ssh::cipher_sizes(cipher);
    guard okz else { print("transport: unknown cipher"); exit(1); }
    let key_c2s = ssh::derive_key(client.hash, k_client, h, 'C', session_id, klen);
    let iv_c2s = ssh::derive_key(client.hash, k_client, h, 'A', session_id, ivlen);
    print("exchange hash ", h.len, " bytes; client-to-server key ", key_c2s.len, " bytes");

    // Packets, client to server: the server derives the same keys.
    var tx = ssh::packet_cipher(cipher, mac, key_c2s, iv_c2s, "");
    var rx = ssh::packet_cipher(cipher, mac, ssh::derive_key(server.hash, k_server, h, 'C', session_id, klen),
                                ssh::derive_key(server.hash, k_server, h, 'A', session_id, ivlen), "");
    var stream: u8[>..] = [];
    let messages: const u8[:][3] = ["first packet", "second packet", "third"];
    for m in messages { stream.append(ssh::seal_packet(tx, m)); }

    // The receiver finds each packet's length from its first bytes.
    var pos = 0;
    var got = 0;
    while pos < stream.len {
        let n = ssh::packet_length(rx, stream[pos..]);
        guard n > 0 else { print("transport: a bad length"); exit(1); }
        let payload, ok = ssh::open_packet(rx, stream[pos..pos + n]);
        guard ok && payload == messages[got] else { print("transport: a packet did not open"); exit(1); }
        pos += n;
        got++;
    }
    print(got, " packets sealed and opened, ", stream.len, " bytes on the wire");

    // A changed byte does not open.
    var bad = ssh::seal_packet(tx, "tampered");
    bad[bad.len - 1] ^= 1;
    let p, okb = ssh::open_packet(rx, bad);
    guard !okb else { print("transport: a changed packet opened"); exit(1); }
    print("a changed packet: refused");
}

fn main() {
    run();
}
