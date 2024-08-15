FROM golang:1.23-alpine as builder
ARG PKG=github.com/crutonjohn/external-dns-opnsense-webhook
ARG VERSION=dev
ARG REVISION=dev
WORKDIR /build
COPY . .
RUN go build -ldflags "-s -w -X main.Version=${VERSION} -X main.Gitsha=${REVISION}" ./cmd/webhook

FROM gcr.io/distroless/static-debian12:nonroot
USER 8675:8675
COPY --from=builder --chmod=555 /build/webhook /external-dns-opnsense-webhook
EXPOSE 8888/tcp
ENTRYPOINT ["/external-dns-opnsense-webhook"]
