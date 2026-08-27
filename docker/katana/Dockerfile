# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file Dockerfile
# @brief Containerized katana runtime for web crawling and attack surface discovery.
#
# This Docker image provides a Go-based environment with a pinned version of
# katana. It is used by Deadbolt to perform advanced web crawling, JavaScript
# parsing, and endpoint discovery during reconnaissance workflows.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

# Compile in an isolated build stage so the runtime does not carry Go.
FROM golang:1.26-alpine AS builder

ARG TOOL_VERSION

# Install build dependencies required for katana.
RUN apk add --no-cache ca-certificates git build-base libc-dev

# Enable CGO for native dependency support
ENV CGO_ENABLED=1

# Install a pinned katana version for deterministic builds
RUN go install "github.com/projectdiscovery/katana/cmd/katana@v${TOOL_VERSION}"

# Chromium is present only at runtime and enables the opt-in Deep SPA profile.
FROM alpine:3.23

RUN apk add --no-cache \
    ca-certificates \
    chromium \
    freetype \
    harfbuzz \
    nss \
    ttf-freefont

COPY --from=builder /go/bin/katana /usr/local/bin/katana

ENV CHROME_BIN=/usr/bin/chromium-browser

# Run katana CLI by default when the container starts
ENTRYPOINT ["katana"]
