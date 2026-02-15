# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file Dockerfile
# @brief Containerized LinkFinder runtime for JavaScript endpoint extraction.
#
# This Docker image provides a minimal Python environment for running
# LinkFinder at a pinned commit for deterministic builds. It is used by
# Deadbolt during web enumeration to extract embedded endpoints from
# JavaScript resources.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

FROM python:3.12-alpine

RUN apk add --no-cache git

# Install LinkFinder at pinned commit for reproducibility
RUN git clone https://github.com/GerbenJavado/LinkFinder.git /opt/linkfinder \
 && cd /opt/linkfinder \
 && git checkout 1debac5 \
 && pip install --no-cache-dir -r requirements.txt

WORKDIR /opt/linkfinder

ENTRYPOINT ["python", "linkfinder.py"]