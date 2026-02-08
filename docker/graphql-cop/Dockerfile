FROM python:3.12-slim

WORKDIR /opt/graphql-cop

# Minimal system deps
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Clone graphql-cop
RUN git clone https://github.com/dolevf/graphql-cop.git .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose CLI
ENTRYPOINT ["python", "graphql-cop.py"]