# eapol_test, wpa_supplicant's RADIUS EAP tester, built from hostap 2.11:
# the peer that tests radiusd's EAP methods.
FROM ubuntu:22.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential git ca-certificates pkg-config libssl-dev && \
    git clone --depth 1 --branch hostap_2_11 https://w1.fi/hostap.git /src && \
    cd /src/wpa_supplicant && \
    printf 'CONFIG_EAPOL_TEST=y\nCONFIG_DRIVER_NONE=y\nCONFIG_TLS=openssl\nCONFIG_IEEE8021X_EAPOL=y\nCONFIG_EAP_TLS=y\nCONFIG_EAP_PEAP=y\nCONFIG_EAP_TTLS=y\nCONFIG_EAP_MSCHAPV2=y\nCONFIG_EAP_MD5=y\nCONFIG_EAP_GTC=y\nCONFIG_TLSV12=y\nCONFIG_TLSV13=y\nCONFIG_CTRL_IFACE=y\n' > .config && \
    make -j8 eapol_test && cp eapol_test /usr/local/bin/ && rm -rf /src
ENTRYPOINT ["eapol_test"]
