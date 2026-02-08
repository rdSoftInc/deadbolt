FROM golang:1.25-alpine

RUN apk add --no-cache ca-certificates git

RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.7.0

RUN nuclei -update-templates

ENTRYPOINT ["nuclei"]