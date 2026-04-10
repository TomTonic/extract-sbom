FROM ubuntu:24.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        jq \
        p7zip-full \
        unshield \
    && if [ ! -x /usr/bin/7zz ] && [ -x /usr/bin/7z ]; then ln -s /usr/bin/7z /usr/local/bin/7zz; fi \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/extract-sbom

COPY dist/extract-sbom-linux-amd64 /opt/extract-sbom/extract-sbom
COPY .github/release-test/run-release-test.sh /opt/extract-sbom/run-release-test.sh
COPY .github/release-test/expected-delivery-paths.txt /opt/extract-sbom/testdata/expected-delivery-paths.txt
COPY integration/testdata/release/release-happy-path.zip /opt/extract-sbom/testdata/release-happy-path.zip

RUN chmod +x /opt/extract-sbom/extract-sbom /opt/extract-sbom/run-release-test.sh

ENTRYPOINT ["/opt/extract-sbom/run-release-test.sh"]
