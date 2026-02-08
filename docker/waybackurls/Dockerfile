FROM golang:1.25-alpine

RUN apk add --no-cache ca-certificates git

RUN go install github.com/tomnomnom/waybackurls@v0.1.0

ENTRYPOINT ["waybackurls"]