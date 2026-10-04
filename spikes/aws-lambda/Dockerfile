FROM golang:1.27.1 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY verification ./verification
COPY spikes/go.mod spikes/go.sum ./spikes/
COPY spikes/harness ./spikes/harness
COPY spikes/cloud ./spikes/cloud
COPY spikes/aws-lambda ./spikes/aws-lambda
WORKDIR /src/spikes
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o /bootstrap ./aws-lambda
FROM public.ecr.aws/lambda/provided:al2023
COPY --from=build /bootstrap /var/runtime/bootstrap
ENTRYPOINT ["/var/runtime/bootstrap"]
