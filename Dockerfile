# Build stage
FROM golang:1.22-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/openpass-api ./cmd/server \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/migrate-sqlite ./cmd/migrate-sqlite

# Runtime stage
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata \
 && adduser -D -u 10001 openpass

COPY --from=build /out/openpass-api /usr/local/bin/openpass-api
COPY --from=build /out/migrate-sqlite /usr/local/bin/migrate-sqlite

# The app key lives on the /data volume so it survives container replacement.
ENV OPENPASS_ADDR=:8080 \
    OPENPASS_SECRET_FILE=/data/openpass.secret
VOLUME /data

USER openpass
EXPOSE 8080
ENTRYPOINT ["openpass-api"]
