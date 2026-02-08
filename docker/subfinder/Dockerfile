FROM golang:1.25-alpine

RUN apk add --no-cache ca-certificates git

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.12.0

ENTRYPOINT ["subfinder"]