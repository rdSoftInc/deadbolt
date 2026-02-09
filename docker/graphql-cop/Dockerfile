# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file Dockerfile
# @brief Containerized graphql-cop runtime for GraphQL security analysis.
#
# This Docker image provides a minimal Python-based environment for running
# graphql-cop, a tool used to analyze GraphQL endpoints for common security
# issues, misconfigurations, and schema weaknesses. It is used by Deadbolt
# during GraphQL reconnaissance and assessment workflows.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

# Use a slim Python base image to reduce image size
FROM python:3.12-slim

# Set working directory for the graphql-cop tool
WORKDIR /opt/graphql-cop

# Install minimal system dependencies required for runtime and cloning
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Clone the graphql-cop repository into the container
RUN git clone https://github.com/dolevf/graphql-cop.git .

# Install Python dependencies required by graphql-cop
RUN pip install --no-cache-dir -r requirements.txt

# Run graphql-cop CLI by default when the container starts
ENTRYPOINT ["python", "graphql-cop.py"]