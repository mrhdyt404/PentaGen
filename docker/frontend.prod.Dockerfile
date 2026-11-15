# Hardened production Dockerfile for PentaGen Frontend Dashboard
# 1. Build Stage
FROM node:20-alpine AS builder

WORKDIR /build
COPY frontend/package.json ./
RUN npm install

COPY frontend/ ./
RUN npm run build

# 2. Production Nginx Runtime Stage (Non-root)
FROM nginxinc/nginx-unprivileged:alpine-slim AS runner

COPY --from=builder /build/dist /usr/share/nginx/html
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 8080

HEALTHCHECK --interval=20s --timeout=3s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
