FROM golang:1.25-alpine

RUN apk add --no-cache ca-certificates git

RUN go install github.com/lc/gau/v2/cmd/gau@v2.2.4

ENTRYPOINT ["gau"]