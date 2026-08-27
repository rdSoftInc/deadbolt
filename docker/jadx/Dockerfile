# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file Dockerfile
# @brief Containerized jadx runtime for Android decompilation.
#
# This Docker image provides a minimal Java-based environment for running
# jadx, a static analysis and decompilation tool used to inspect Android
# application bytecode. It is used by Deadbolt for reverse engineering and
# code inspection during Android security analysis workflows.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

# Use Amazon Corretto JDK for stable Java runtime support
FROM amazoncorretto:21-alpine-jdk

ARG TOOL_VERSION

# Install minimal runtime dependencies required for downloading and extracting jadx
RUN apk add --no-cache wget unzip

# Download and install a pinned jadx release
RUN wget "https://github.com/skylot/jadx/releases/download/v${TOOL_VERSION}/jadx-${TOOL_VERSION}.zip" \
 && unzip "jadx-${TOOL_VERSION}.zip" -d /opt/jadx \
 && chmod +x /opt/jadx/bin/jadx \
 && ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx \
 && rm "jadx-${TOOL_VERSION}.zip"

# Run jadx CLI by default when the container starts
ENTRYPOINT ["jadx"]
