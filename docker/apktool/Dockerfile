# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file Dockerfile
# @brief Containerized Apktool runtime for Android static analysis.
#
# This Docker image provides a minimal, deterministic Apktool environment
# used by Deadbolt for Android reverse engineering and manifest/resource
# extraction.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

FROM amazoncorretto:21-alpine-jdk

# Install minimal runtime dependencies required by Apktool
RUN apk add --no-cache wget unzip

# Install Apktool:
#   - Fetch official wrapper script
#   - Fetch pinned Apktool JAR version
#   - Install into /usr/local/bin for CLI execution
RUN wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool \
 && wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.12.1.jar \
 && mv apktool_2.12.1.jar /usr/local/bin/apktool.jar \
 && chmod +x apktool \
 && mv apktool /usr/local/bin/apktool

# Run container as Apktool CLI by default
ENTRYPOINT ["apktool"]