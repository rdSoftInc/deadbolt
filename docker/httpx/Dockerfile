# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file Dockerfile
# @brief Containerized httpx runtime for HTTP probing and service discovery.
#
# This Docker image provides a minimal Go-based environment with a pinned
# version of httpx. It is used by Deadbolt to probe HTTP services, enumerate
# supported protocols, and collect response metadata during reconnaissance
# and validation workflows.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

# Use a minimal Alpine-based Go image for small footprint and fast builds
FROM golang:1.25-alpine

# Install runtime dependencies required for Go tooling and HTTPS access
RUN apk add --no-cache ca-certificates git

# Install a pinned httpx version for deterministic builds
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@v1.8.1

# Run httpx CLI by default when the container starts
ENTRYPOINT ["httpx"]