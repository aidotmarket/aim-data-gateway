FROM golang:1.27.3@sha256:f20d83a83e18dbd2a4714b8ffd4b30b287b6243962dd75608e86abcc63ba4efc AS builder
ARG VERSION=0.0.0-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w -buildid= -X main.version=${VERSION}" -o /aim-gateway ./cmd/aim-gateway
RUN mkdir -p /state /config /sources/data

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=builder /aim-gateway /aim-gateway
COPY --from=builder --chown=65532:65532 /state /state
COPY --from=builder /config /config
COPY --from=builder /sources /sources
USER 65532:65532
ENTRYPOINT ["/aim-gateway"]
CMD ["run"]
