# Built from backend/ as context:  docker compose build api
FROM oven/bun:1.4
WORKDIR /app
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production
COPY .env ./
COPY src ./src
CMD ["bun", "run", "service:api"]
