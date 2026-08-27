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

FROM golang:1.26-alpine

ARG TOOL_VERSION

# dnsx v1.3.0 incorrectly reports its embedded CLI version as 1.2.3.
# Record the source release explicitly for reliable lifecycle verification.
LABEL io.deadbolt.tool.version="${TOOL_VERSION}"

# Install runtime dependencies
RUN apk add --no-cache ca-certificates git

# Install pinned dnsx version for deterministic builds
RUN go install "github.com/projectdiscovery/dnsx/cmd/dnsx@v${TOOL_VERSION}"

# Run dnsx CLI by default
ENTRYPOINT ["dnsx"]
