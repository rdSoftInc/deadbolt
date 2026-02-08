FROM golang:1.25-alpine

RUN apk add --no-cache ca-certificates git

RUN go install github.com/projectdiscovery/httpx/cmd/httpx@v1.8.1

ENTRYPOINT ["httpx"]