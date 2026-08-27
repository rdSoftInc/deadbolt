FROM python:3.13-alpine
ARG TOOL_VERSION=2.2.7
RUN pip install --no-cache-dir "arjun==${TOOL_VERSION}"
LABEL io.deadbolt.tool="arjun" io.deadbolt.tool.version="${TOOL_VERSION}"
ENTRYPOINT ["arjun"]
