FROM golang:1.25.0@sha256:5502b0e56fca23feba76dbc5387ba59c593c02ccc2f0f7355871ea9a0852cebe AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /aim-gateway ./cmd/aim-gateway
RUN mkdir -p /state /config /sources/data

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=builder /aim-gateway /aim-gateway
COPY --from=builder --chown=65532:65532 /state /state
COPY --from=builder /config /config
COPY --from=builder /sources /sources
USER 65532:65532
ENTRYPOINT ["/aim-gateway"]
CMD ["run"]
