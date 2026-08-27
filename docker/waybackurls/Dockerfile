# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file Dockerfile
# @brief Containerized waybackurls runtime for historical URL discovery.
#
# This Docker image provides a minimal Go-based environment with a pinned
# version of waybackurls. It is used by Deadbolt to retrieve historical URLs
# from public archives during reconnaissance and surface mapping workflows.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

# Use a minimal Alpine-based Go image for small footprint and fast builds
FROM golang:1.26-alpine

ARG TOOL_VERSION
LABEL io.deadbolt.tool.version="${TOOL_VERSION}"

# Install runtime dependencies required for Go tooling and HTTPS access
RUN apk add --no-cache ca-certificates git

# Install a pinned waybackurls version for deterministic builds
RUN go install "github.com/tomnomnom/waybackurls@v${TOOL_VERSION}"

# Run waybackurls CLI by default when the container starts
ENTRYPOINT ["waybackurls"]
