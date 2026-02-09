# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file Dockerfile
# @brief Containerized subfinder runtime for subdomain enumeration.
#
# This Docker image provides a minimal Go-based environment with a pinned
# version of subfinder. It is used by Deadbolt to enumerate subdomains from
# multiple sources during reconnaissance and asset discovery workflows.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

# Use a minimal Alpine-based Go image for small footprint and fast builds
FROM golang:1.25-alpine

# Install runtime dependencies required for Go tooling and HTTPS access
RUN apk add --no-cache ca-certificates git

# Install a pinned subfinder version for deterministic builds
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.12.0

# Run subfinder CLI by default when the container starts
ENTRYPOINT ["subfinder"]