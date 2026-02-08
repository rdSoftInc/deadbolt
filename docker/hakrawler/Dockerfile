FROM golang:1.25-alpine

RUN apk add --no-cache ca-certificates git

RUN go install github.com/hakluke/hakrawler@latest

ENTRYPOINT ["hakrawler"]