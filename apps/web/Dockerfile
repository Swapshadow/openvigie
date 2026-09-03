FROM node:22.23.2-bookworm-slim

WORKDIR /app

RUN npm install --global pnpm@11.19.0

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm config set fetch-timeout 900000 \
    && pnpm config set fetch-retries 8 \
    && pnpm config set fetch-retry-maxtimeout 180000 \
    && pnpm install --frozen-lockfile

COPY . .

RUN pnpm build

EXPOSE 3000

CMD ["pnpm", "start", "--", "--host", "0.0.0.0"]
