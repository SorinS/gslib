# PyKMIP's server (KMIP 1.0-2.0 over TLS on 5696), for gslib's kmip interop.
# Its master (4815637, the commit kmip/tables.goose comes from): the 0.10.0
# release cannot load public keys for Signature Verify under cryptography 42.
FROM python:3.11-slim
RUN pip install --no-cache-dir \
    https://github.com/OpenKMIP/PyKMIP/archive/481563735cc96eb9f7b363df3c24b2ea68b9353f.tar.gz
ENTRYPOINT ["pykmip-server"]
