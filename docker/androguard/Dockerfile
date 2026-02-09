# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file Dockerfile
# @brief Containerized Androguard runtime for Android static analysis.
#
# This Docker image provides a minimal Python-based environment with a pinned
# version of Androguard. Androguard is used by Deadbolt for advanced Android
# static analysis such as permission inspection, intent-filter analysis,
# component exposure mapping, and inter-component communication modeling.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

FROM python:3.11-slim

# Install minimal system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install pinned Androguard version for deterministic builds
RUN pip install --no-cache-dir androguard==4.1.3

# Set default working directory
WORKDIR /work

# Default entrypoint executes androguard CLI
ENTRYPOINT ["androguard"]