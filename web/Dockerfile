# web — the Next.js console (App Router). Build context is THIS directory (self-contained, no
# sibling modules needed). Build from web/:
#   docker build -t proxy-monster-web .
#
# Runtime env: PM_PROXY_TARGET (control-plane base URL the /api and /auth rewrites forward to —
# see next.config.ts; set this to wherever control-plane is reachable from inside the
# cluster/VPC, e.g. http://control-plane.internal:8080) and NEXT_LOCALE-independent i18n (cookie-
# based, no env needed). PORT/HOSTNAME below make the standalone server listen on 0.0.0.0 so it's
# reachable from outside the container — the generated server.js defaults HOSTNAME to "localhost"
# otherwise, which is unreachable from outside the container network namespace.

# Match ../mise.toml's node/pnpm pins — bump both together.
FROM node:24-alpine AS base
RUN corepack enable && corepack prepare pnpm@10.22.0 --activate

FROM base AS deps
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# `prebuild` (package.json) copies the Cedar WASM binary into public/cedar/ before `next build`.
RUN pnpm build

# ---- Runtime ----
FROM base AS runner
WORKDIR /app
ENV NODE_ENV=production

RUN addgroup --system --gid 10001 nodejs && adduser --system --uid 10001 --ingroup nodejs nextjs

# `output: "standalone"` (next.config.ts) traces the minimal node_modules subset the built server
# needs into .next/standalone — this is NOT the full node_modules tree from the builder stage.
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs
ENV PORT=41300
ENV HOSTNAME=0.0.0.0
EXPOSE 41300

HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=5 \
    CMD wget -qO- --spider "http://127.0.0.1:${PORT}/" || exit 1

CMD ["node", "server.js"]
