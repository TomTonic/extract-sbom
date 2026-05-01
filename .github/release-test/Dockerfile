FROM debian:13-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        jq \
        p7zip-full \
        unshield \
    && rm -rf /var/lib/apt/lists/*

# Install latest stable Grype for vulnerability roundtrip test.
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sh -s -- -b /usr/local/bin

WORKDIR /opt/extract-sbom

COPY dist/extract-sbom-linux-amd64 /opt/extract-sbom/extract-sbom
COPY .github/release-test/run-release-test.sh /opt/extract-sbom/run-release-test.sh
COPY .github/release-test/expected-delivery-paths.txt /opt/extract-sbom/testdata/expected-delivery-paths.txt
COPY integration/vendorsuite/testdata/vendor-suite-3.2.zip /opt/extract-sbom/testdata/vendor-suite-3.2.zip

RUN chmod +x /opt/extract-sbom/extract-sbom /opt/extract-sbom/run-release-test.sh

ENTRYPOINT ["/opt/extract-sbom/run-release-test.sh"]
