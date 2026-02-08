FROM golang:1.25-alpine 

RUN apk add --no-cache ca-certificates git build-base libc-dev

# Disable CGO flags confusion
ENV CGO_ENABLED=1

RUN go install github.com/projectdiscovery/katana/cmd/katana@v1.4.0

ENTRYPOINT ["katana"]