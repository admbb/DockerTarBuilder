FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY web/ ./
RUN npm run build

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal/ ./internal/
COPY cmd/ ./cmd/
COPY web/embed.go ./web/embed.go
COPY --from=web /src/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/netflow-v2 ./cmd/netflow-v2

FROM alpine:3.21
RUN apk add --no-cache ca-certificates && addgroup -S netflow && adduser -S -G netflow netflow && mkdir -m 0700 /data && chown netflow:netflow /data
COPY --from=build /out/netflow-v2 /usr/local/bin/netflow-v2
COPY docs/NETFLOW-UPSTREAM-LICENSE internal/catalog/V2FLY-LICENSE.txt /usr/share/licenses/netflow-v2/
USER netflow
ENV APP_PORT=8088 DB_PATH=/data/app.db
VOLUME /data
EXPOSE 8088
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD wget -q -O /dev/null "http://127.0.0.1:${APP_PORT}/healthz" || exit 1
ENTRYPOINT ["/usr/local/bin/netflow-v2"]
