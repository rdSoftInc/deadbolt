FROM golang:1.25-alpine

RUN apk add --no-cache ca-certificates git

RUN go install github.com/ffuf/ffuf/v2@v2.1.0

ENTRYPOINT ["ffuf"]