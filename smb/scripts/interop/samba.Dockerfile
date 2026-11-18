# Samba 4.17 (Debian 12) for smb's interop: smbd as a standalone file
# server, the AD DC for Kerberos, and smbclient to check what gslib wrote.
FROM debian:bookworm-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      samba samba-ad-dc samba-ad-provision samba-dsdb-modules samba-vfs-modules smbclient winbind krb5-user && \
    rm -rf /var/lib/apt/lists/*
