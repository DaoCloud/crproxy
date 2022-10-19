FROM golang:alpine AS builder
WORKDIR /go/src/github.com/wzshiming/crproxy/
COPY . .
ENV CGO_ENABLED=0
RUN go install ./cmd/crproxy

FROM alpine
EXPOSE 8080
COPY --from=builder /go/bin/crproxy /usr/local/bin/
ENTRYPOINT [ "/usr/local/bin/crproxy" ]
