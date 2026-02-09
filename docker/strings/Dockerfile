# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file Dockerfile
# @brief Containerized strings utility for binary analysis.
#
# This Docker image provides a minimal Alpine-based environment exposing the
# strings utility. It is used by Deadbolt to extract printable strings from
# binaries during static analysis and reverse engineering workflows.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

# Use a minimal Alpine base image
FROM alpine:3.20

# Install binutils to provide the strings utility and grep for filtering
RUN apk add --no-cache binutils grep

# Run strings by default when the container starts
ENTRYPOINT ["strings"]