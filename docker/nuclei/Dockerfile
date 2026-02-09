# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file Dockerfile
# @brief Containerized nuclei runtime for vulnerability scanning.
#
# This Docker image provides a minimal Go-based environment with a pinned
# version of nuclei. It is used by Deadbolt to execute template-based
# vulnerability scans and security checks during automated assessment
# workflows.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

# Use a minimal Alpine-based Go image for small footprint and fast builds
FROM golang:1.25-alpine

# Install runtime dependencies required for Go tooling and HTTPS access
RUN apk add --no-cache ca-certificates git

# Install a pinned nuclei version for deterministic builds
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.7.0

# Update nuclei templates during build time
RUN nuclei -update-templates

# Run nuclei CLI by default when the container starts
ENTRYPOINT ["nuclei"]