# ── EchoVault browser client (Next.js 16 / React 19) ─────────────────────────
# Multi-stage: build the production bundle, then run `next start`.
# We run a PRODUCTION build (not `next dev`) so we don't have to fight the
# dev-only allowedDevOrigins cross-origin check — production ignores it.

# ---- build stage ----
FROM node:22-alpine AS build
WORKDIR /app

# The API base URL is baked into the browser bundle at BUILD time
# (NEXT_PUBLIC_* vars are inlined by Next.js). Point it at the echo server the
# browser should reach — the server's own TLS port locally (D030), the proxy's
# public name in the cloud. page.tsx derives the WebSocket URL (https → wss).
ARG NEXT_PUBLIC_API_URL=https://localhost:8443
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# ---- run stage ----
FROM node:22-alpine AS run
WORKDIR /app
ENV NODE_ENV=production

# Copy only what `next start` needs to serve the prebuilt app.
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/.next ./.next
COPY --from=build /app/public ./public
COPY --from=build /app/next.config.ts ./next.config.ts

EXPOSE 3000

# Bind all interfaces so the published port reaches it.
CMD ["npx", "next", "start", "-H", "0.0.0.0", "-p", "3000"]
