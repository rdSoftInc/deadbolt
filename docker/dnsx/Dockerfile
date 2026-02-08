FROM golang:1.25-alpine

RUN apk add --no-cache ca-certificates git

RUN go install github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.3

ENTRYPOINT ["dnsx"]