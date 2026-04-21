FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install git (required by go mod to fetch from GitHub)
RUN apk add --no-cache git

# Copy all source files (go.sum excluded via .dockerignore)
COPY . .

# Force remove any bad go.sum, then generate fresh and download
RUN rm -f go.sum && go mod tidy && go mod download

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -o m-sd-jwt-gateway .

# Final minimal runtime image
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY --from=builder /app/m-sd-jwt-gateway .

EXPOSE 8080

CMD ["./m-sd-jwt-gateway"]