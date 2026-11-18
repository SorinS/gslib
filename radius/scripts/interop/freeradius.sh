#!/bin/sh
# FreeRADIUS 3.2 for radius's interop, in WORK (the first argument): its
# stock configuration with test certificates (a CA, the server's, clients'
# in RSA and P-256), the user alice, PEAP/TTLS/EAP-TLS up to TLS 1.3,
# RadSec; published on loopback only (1812, 1813, 2083). Then a second
# FreeRADIUS on loopback, a proxy: user@radsec.example on 21812 goes over
# RadSec to gslib's radiusd on 12083.
set -e
WORK=$1
IMAGE=freeradius/freeradius-server:latest-3.2
mkdir -p "$WORK" && cd "$WORK"
rm -rf raddb-orig raddb raddb-proxy certs
id=$(docker create $IMAGE) && docker cp -L $id:/etc/freeradius/. raddb-orig >/dev/null && docker rm $id >/dev/null
cp -r raddb-orig raddb && mkdir certs
cd certs
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=gslib test CA" -keyout ca.key -out ca.pem 2>/dev/null
mk() { # name key-args subject extendedKeyUsage
    openssl req -newkey $2 -nodes -subj "$3" -keyout $1.key -out $1.csr 2>/dev/null
    printf "extendedKeyUsage=%s\nsubjectAltName=DNS:radius.example.com\n" "$4" > $1.ext
    openssl x509 -req -in $1.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 3650 -extfile $1.ext -out $1.pem 2>/dev/null
}
mk server rsa:2048 "/CN=radius.example.com" serverAuth
mk client rsa:2048 "/CN=alice" clientAuth
mk client-ec "ec -pkeyopt ec_paramgen_curve:P-256" "/CN=alice" clientAuth
mk radsec-client "ec -pkeyopt ec_paramgen_curve:P-256" "/CN=nas.example.com" clientAuth
openssl dhparam -dsaparam -out dh 2048 2>/dev/null
for f in server radsec-client; do cat $f.pem $f.key > $f-bundle.pem; done
chmod 644 *
cd ..
R=raddb
cp certs/ca.pem $R/certs/ca.pem; cp certs/server-bundle.pem $R/certs/server.pem; cp certs/dh $R/certs/dh
cp certs/radsec-client-bundle.pem $R/certs/client.pem
sed -i 's/private_key_password = whatever/private_key_password = ""/' $R/mods-available/eap $R/sites-available/tls
sed -i 's/tls_max_version = "1.2"/tls_max_version = "1.3"/' $R/mods-available/eap
printf 'client docker {\n\tipaddr = 0.0.0.0/0\n\tsecret = testing123\n}\n' >> $R/clients.conf
sed -i '/^clients radsec {/,/^}/ s/ipaddr = 127.0.0.1/ipaddr = 0.0.0.0\/0/' $R/sites-available/tls
ln -s ../sites-available/tls $R/sites-enabled/tls
printf 'alice\tCleartext-Password := "alice-pw"\n\tReply-Message := "Hello, %%{User-Name}"\n' > $R/mods-config/files/authorize
# The proxy: loopback only, other ports, no IPv6, no RadSec listener; its
# home server is gslib's.
cp -r raddb raddb-proxy
python3 - <<'P'
import re
p = 'raddb-proxy/sites-available/default'
s = open(p).read()
out = []; i = 0; ports = iter(['21812', '21813'])
while True:
    j = s.find('listen {', i)
    if j < 0: out.append(s[i:]); break
    k = s.index('\n}', j) + 2
    block = s[j:k]
    out.append(s[i:j])
    if not re.search(r'^\s*ipv6addr\s*=', block, re.M):
        block = re.sub(r'^(\s*)ipaddr = \*', r'\1ipaddr = 127.0.0.1', block, flags=re.M)
        block = re.sub(r'^(\s*)port = 0', r'\1port = ' + next(ports), block, count=1, flags=re.M)
        out.append(block)
    i = k
open(p, 'w').write(''.join(out))
p = 'raddb-proxy/sites-available/tls'
s = open(p).read()
s = s[:s.index('listen {')] + s[s.index('clients radsec {'):]
s = s.replace('home_server tls {\n\tipaddr = 127.0.0.1\n\tport = 2083', 'home_server tls {\n\tipaddr = 127.0.0.1\n\tport = 12083')
s += 'realm radsec.example {\n\tauth_pool = tls\n}\n'
open(p, 'w').write(s)
P
rm raddb-proxy/sites-enabled/inner-tunnel
chmod -R a+rX raddb raddb-proxy certs
docker rm -f gs-radius gs-radius-proxy >/dev/null 2>&1 || true
docker run -d --name gs-radius -v "$PWD/raddb:/etc/freeradius" -p 127.0.0.1:1812:1812/udp -p 127.0.0.1:1813:1813/udp -p 127.0.0.1:2083:2083/tcp $IMAGE -fxx -l stdout >/dev/null
docker run -d --name gs-radius-proxy --network host -v "$PWD/raddb-proxy:/etc/freeradius" $IMAGE -fxx -l stdout >/dev/null
sleep 3
docker logs gs-radius 2>&1 | grep -q "Ready to process requests" && docker logs gs-radius-proxy 2>&1 | grep -q "Ready to process requests"
