FROM golang:1.26-alpine AS builder
ARG TOOL_VERSION=1.3.0
RUN go install "github.com/projectdiscovery/tlsx/cmd/tlsx@v${TOOL_VERSION}"
FROM alpine:3.23
ARG TOOL_VERSION=1.3.0
RUN apk add --no-cache ca-certificates
COPY --from=builder /go/bin/tlsx /usr/local/bin/tlsx
LABEL io.deadbolt.tool="tlsx" io.deadbolt.tool.version="${TOOL_VERSION}"
ENTRYPOINT ["tlsx"]
