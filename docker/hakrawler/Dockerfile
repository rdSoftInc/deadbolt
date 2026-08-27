# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file Dockerfile
# @brief Containerized hakrawler runtime for web crawling and link discovery.
#
# This Docker image provides a minimal Go-based environment for running
# hakrawler, a web crawler used to discover endpoints, links, and parameters
# from target web applications during reconnaissance workflows in Deadbolt.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

# Use a minimal Alpine-based Go image for small footprint and fast builds
FROM golang:1.26-alpine

# Install runtime dependencies required for Go tooling and HTTPS access
RUN apk add --no-cache ca-certificates git

# Pin the source revision so rebuilds remain reproducible.
ARG TOOL_COMMIT
LABEL io.deadbolt.tool.version="${TOOL_COMMIT}"
RUN go install "github.com/hakluke/hakrawler@${TOOL_COMMIT}"

# Run hakrawler CLI by default when the container starts
ENTRYPOINT ["hakrawler"]
