#!/bin/sh
# Samba for smb's interop, in WORK (the first argument), on loopback only:
#   gs-smb         127.0.0.1:4451  signing and encryption as the client
#                                  asks; shares pub, enc (encryption
#                                  required for it alone) and IPC$
#   gs-smb-strict  127.0.0.1:4452  signing mandatory, encryption required
#                                  for every session
#   gs-smb-dc      127.0.0.1:4453  an AD DC (realm SMB.TEST) with its KDC
#                                  on 127.0.0.1:8853, for Kerberos
# The user alice (the password is the second argument) on each.
set -e
WORK=$1
PW=$2
IMAGE=gs-samba
HERE=$(cd "$(dirname "$0")" && pwd)
docker build -q -t $IMAGE -f "$HERE/samba.Dockerfile" "$HERE" >/dev/null
mkdir -p "$WORK" && cd "$WORK"
docker rm -f gs-smb gs-smb-strict gs-smb-dc >/dev/null 2>&1 || true

conf() { # name extra-global-lines
    cat > $1.conf <<CONF
[global]
  server role = standalone server
  workgroup = TESTGROUP
  netbios name = SMBTEST
  security = user
  map to guest = never
  restrict anonymous = 0
  server min protocol = SMB2_02
  server max protocol = SMB3_11
  ntlm auth = ntlmv2-only
  disable netbios = yes
  smb ports = 445
  load printers = no
  printing = bsd
  printcap name = /dev/null
  disable spoolss = yes
  log file = /var/log/samba/log.%m
  log level = 1
$2
[pub]
  path = /srv/pub
  read only = no
  create mask = 0644
[enc]
  path = /srv/enc
  read only = no
  server smb encrypt = required
CONF
}
conf plain ""
conf strict "  server signing = mandatory
  server smb encrypt = required"

export PW
run_env() { docker run -d -e PW="$PW" "$@" >/dev/null; }
for spec in "gs-smb 4451 plain" "gs-smb-strict 4452 strict"; do
    set -- $spec
    run_env --name $1 -p 127.0.0.1:$2:445 -v "$WORK/$3.conf:/etc/samba/smb.conf:ro" $IMAGE \
      sh -c 'mkdir -p /srv/pub /srv/enc && chmod 777 /srv/pub /srv/enc && useradd -M alice && \
             printf "%s\n%s\n" "$PW" "$PW" | smbpasswd -s -a alice >/dev/null && exec smbd -F --no-process-group --debug-stdout'
done

# The AD DC: provisioned at start (SYS_ADMIN for the sysvol's security.*
# extended attributes), then samba in the foreground.
run_env --name gs-smb-dc --hostname dc --cap-add SYS_ADMIN -p 127.0.0.1:4453:445 -p 127.0.0.1:8853:88 -p 127.0.0.1:8853:88/udp $IMAGE \
  sh -c 'rm -f /etc/samba/smb.conf && \
         samba-tool domain provision --realm=SMB.TEST --domain=SMBTEST --server-role=dc --dns-backend=NONE \
           --host-name=dc --adminpass="Adm-$PW" --option="ntlm auth = ntlmv2-only" >/dev/null && \
         samba-tool user setexpiry Administrator --noexpiry >/dev/null && \
         samba-tool user create alice "$PW" >/dev/null && \
         mkdir -p /srv/pub && chmod 777 /srv/pub && \
         printf "[pub]\n  path = /srv/pub\n  read only = no\n" >> /etc/samba/smb.conf && \
         exec samba -i --no-process-group --debug-stdout'
# Wait for each to listen.
for p in 4451 4452 4453; do
    i=0
    until docker run --rm --network host $IMAGE smbclient -L //127.0.0.1 -p $p -U "alice%$PW" >/dev/null 2>&1 || [ $i -ge 90 ]; do
        i=$((i + 1)); sleep 1
    done
done
