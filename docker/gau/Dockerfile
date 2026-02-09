# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file Dockerfile
# @brief Containerized gau runtime for URL discovery and archive enumeration.
#
# This Docker image provides a minimal Go-based environment with a pinned
# version of gau (GetAllURLs). It is used by Deadbolt to collect known URLs
# from public sources such as search engines and web archives during
# reconnaissance and surface mapping workflows.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

# Use a minimal Alpine-based Go image for small footprint and fast builds
FROM golang:1.25-alpine

# Install runtime dependencies required for Go tooling and HTTPS access
RUN apk add --no-cache ca-certificates git

# Install a pinned gau version for deterministic and reproducible builds
RUN go install github.com/lc/gau/v2/cmd/gau@v2.2.4

# Run gau CLI by default when the container starts
ENTRYPOINT ["gau"]