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

# Use a minimal Alpine-based Go image with build dependencies
FROM golang:1.25-alpine

# Install runtime and build dependencies required for katana
RUN apk add --no-cache ca-certificates git build-base libc-dev

# Enable CGO for native dependency support
ENV CGO_ENABLED=1

# Install a pinned katana version for deterministic builds
RUN go install github.com/projectdiscovery/katana/cmd/katana@v1.4.0

# Run katana CLI by default when the container starts
ENTRYPOINT ["katana"]