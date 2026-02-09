# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file Dockerfile
# @brief Containerized ParamSpider runtime for parameter discovery.
#
# This Docker image provides a minimal Python-based environment for running
# ParamSpider, a tool used to discover hidden and undocumented HTTP parameters
# from web applications. It is used by Deadbolt during parameter enumeration
# and reconnaissance workflows.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

# Use a slim Python base image
FROM python:3.12-slim

# Set the working directory inside the container
WORKDIR /app

# Install git for cloning the ParamSpider repository
RUN apt-get update \
 && apt-get install -y git \
 && rm -rf /var/lib/apt/lists/*

# Clone the ParamSpider repository
RUN git clone https://github.com/devanshbatham/paramspider

# Change the working directory to the cloned repository
WORKDIR /app/paramspider

# Install ParamSpider as a Python package
RUN pip install .

# Run ParamSpider CLI by default when the container starts
ENTRYPOINT ["paramspider"]