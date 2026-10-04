FROM golang:1.27.1 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY verification ./verification
COPY spikes/go.mod spikes/go.sum ./spikes/
COPY spikes/harness ./spikes/harness
COPY spikes/cloud ./spikes/cloud
COPY spikes/r2-container ./spikes/r2-container
WORKDIR /src/spikes
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /server ./r2-container
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /server /server
EXPOSE 8080
ENTRYPOINT ["/server"]
