# Build stage
FROM golang:1.23-alpine AS builder

# Enable toolchain auto-download for newer Go versions
ENV GOTOOLCHAIN=auto

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o melange-server ./cmd/melange-server

# Runtime stage
FROM cgr.dev/chainguard/wolfi-base:latest

# Install required packages for builds (pipelines need these)
RUN apk add --no-cache ca-certificates

COPY --from=builder /app/melange-server /usr/bin/melange-server

# Copy built-in pipelines
COPY --from=builder /app/pkg/build/pipelines /usr/share/melange/pipelines

ENTRYPOINT ["/usr/bin/melange-server"]
