FROM debian:bookworm-slim AS builder

ARG TOOL_VERSION=7.991

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        bzip2 \
        ca-certificates \
        curl \
        libpcap-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Nmap publishes a digest beside every official source release. Validate the
# tarball before compiling so a partial or altered download cannot be built.
RUN curl --fail --location --retry 3 --output nmap.tar.bz2 \
        "https://nmap.org/dist/nmap-${TOOL_VERSION}.tar.bz2" \
    && curl --fail --location --retry 3 --output nmap.digest \
        "https://nmap.org/dist/sigs/nmap-${TOOL_VERSION}.tar.bz2.digest.txt" \
    && expected="$(sed -n '/SHA256/{N;s/.*SHA256 = //;s/[[:space:]]//g;p;q}' nmap.digest | tr '[:upper:]' '[:lower:]')" \
    && test -n "$expected" \
    && echo "$expected  nmap.tar.bz2" | sha256sum --check - \
    && tar -xjf nmap.tar.bz2 --strip-components=1

RUN ./configure --prefix=/usr/local --without-zenmap --without-ndiff \
    && make -j"$(nproc)" \
    && make install DESTDIR=/stage

FROM debian:bookworm-slim

ARG TOOL_VERSION=7.991

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libpcap0.8 \
        libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /stage/ /

LABEL org.opencontainers.image.title="Nmap"
LABEL org.opencontainers.image.source="https://nmap.org/"
LABEL org.opencontainers.image.version="${TOOL_VERSION}"

ENTRYPOINT ["nmap"]
