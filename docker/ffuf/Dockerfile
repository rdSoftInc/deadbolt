# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file Dockerfile
# @brief Containerized ffuf runtime for web fuzzing and content discovery.
#
# This Docker image provides a minimal Go-based environment with a pinned
# version of ffuf (Fuzz Faster U Fool). It is used by Deadbolt for deterministic
# web fuzzing, parameter discovery, and endpoint enumeration during security
# analysis workflows.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

# Use the official release artifact so ffuf's GoReleaser-injected version and
# build metadata are preserved exactly.
FROM alpine:3.23

ARG TOOL_VERSION
ARG TARGETARCH

# Install only the dependencies needed to fetch and verify the release.
RUN apk add --no-cache ca-certificates curl tar

# Download the official platform artifact and verify it against the checksum
# file published with the same GitHub release.
RUN case "${TARGETARCH}" in \
      amd64|arm64|386) FFUF_ARCH="${TARGETARCH}" ;; \
      arm) FFUF_ARCH="armv6" ;; \
      *) echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
 && ARCHIVE="ffuf_${TOOL_VERSION}_linux_${FFUF_ARCH}.tar.gz" \
 && BASE_URL="https://github.com/ffuf/ffuf/releases/download/v${TOOL_VERSION}" \
 && curl -fsSLO "${BASE_URL}/${ARCHIVE}" \
 && curl -fsSLo checksums.txt "${BASE_URL}/ffuf_${TOOL_VERSION}_checksums.txt" \
 && grep " ${ARCHIVE}$" checksums.txt | sha256sum -c - \
 && tar -xzf "${ARCHIVE}" -C /usr/local/bin ffuf \
 && chmod +x /usr/local/bin/ffuf \
 && rm -f "${ARCHIVE}" checksums.txt \
 && ffuf -V

# Run ffuf CLI by default when the container starts
ENTRYPOINT ["ffuf"]
