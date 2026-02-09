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

# Use a minimal Alpine-based Go image for small footprint and fast builds
FROM golang:1.25-alpine

# Install runtime dependencies required for Go tooling and HTTPS access
RUN apk add --no-cache ca-certificates git

# Install a pinned ffuf version to ensure deterministic and reproducible builds
RUN go install github.com/ffuf/ffuf/v2@v2.1.0

# Run ffuf CLI by default when the container starts
ENTRYPOINT ["ffuf"]