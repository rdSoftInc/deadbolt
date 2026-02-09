# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file Dockerfile
# @brief Containerized dnsx runtime for DNS reconnaissance and resolution.
#
# This Docker image provides a minimal Go-based environment with a pinned
# version of ProjectDiscovery's dnsx tool. It is used by Deadbolt for
# DNS enumeration, resolution, and enrichment during security analysis.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

FROM golang:1.25-alpine

# Install runtime dependencies
RUN apk add --no-cache ca-certificates git

# Install pinned dnsx version for deterministic builds
RUN go install github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.3

# Run dnsx CLI by default
ENTRYPOINT ["dnsx"]