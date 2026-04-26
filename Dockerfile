FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
# Build with optimizations: strip debug info to reduce binary size
RUN go build -ldflags="-s -w" -o RealiTLScanner .

FROM alpine:latest
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=build /src/RealiTLScanner .
ENTRYPOINT ["./RealiTLScanner"]
