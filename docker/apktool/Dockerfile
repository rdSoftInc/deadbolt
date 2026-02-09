# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file Dockerfile
# @brief Containerized apktool runtime for Android static analysis.
#
# This Docker image provides a minimal Java-based environment with a pinned
# version of apktool. It is used by Deadbolt during Android static analysis
# to decode APK resources and extract the AndroidManifest.xml for inspection.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

FROM amazoncorretto:21-alpine-jdk

# Install minimal runtime dependencies
RUN apk add --no-cache wget bash

# Working directory for apktool assets
WORKDIR /opt/apktool

# Download pinned apktool JAR for deterministic builds
RUN wget -O apktool.jar \
    https://github.com/iBotPeaches/Apktool/releases/download/v2.12.1/apktool_2.12.1.jar

# Create a minimal wrapper script to invoke the apktool JAR
RUN echo '#!/bin/bash' > /usr/local/bin/apktool && \
    echo 'exec java -jar /opt/apktool/apktool.jar "$@"' >> /usr/local/bin/apktool

# Make wrapper executable
RUN chmod +x /usr/local/bin/apktool

# Verify apktool installation at build time
RUN /usr/local/bin/apktool --version

# Run apktool CLI by default
ENTRYPOINT ["/usr/local/bin/apktool"]