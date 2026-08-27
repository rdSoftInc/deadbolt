FROM golang:1.26-alpine AS builder
ARG TOOL_VERSION=2.6.1
RUN apk add --no-cache git build-base libpcap-dev
RUN CGO_ENABLED=1 go install "github.com/projectdiscovery/naabu/v2/cmd/naabu@v${TOOL_VERSION}"

FROM alpine:3.23
ARG TOOL_VERSION=2.6.1
RUN apk add --no-cache ca-certificates libpcap nmap
COPY --from=builder /go/bin/naabu /usr/local/bin/naabu
LABEL org.opencontainers.image.title="Deadbolt Naabu" org.opencontainers.image.version="${TOOL_VERSION}" io.deadbolt.tool="naabu" io.deadbolt.tool.version="${TOOL_VERSION}"
ENTRYPOINT ["naabu"]
