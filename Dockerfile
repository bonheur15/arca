# syntax=docker/dockerfile:1.7

# Arca embeds the built React application into a static Go binary. Keeping the
# frontend and Go toolchains in build-only stages makes the final image small
# and removes compilers, package managers, and source code from production.

FROM node:24-bookworm-slim AS web-build

ENV COREPACK_HOME=/tmp/corepack \
    PNPM_HOME=/pnpm \
    CI=true
ENV PATH=${PNPM_HOME}:${PATH}

RUN corepack enable \
    && corepack install --global pnpm@10.33.0

WORKDIR /src/web

# Keep dependency installation cacheable when application sources change.
COPY web/package.json web/pnpm-lock.yaml ./
RUN --mount=type=cache,id=arca-pnpm,target=/pnpm/store \
    pnpm install --frozen-lockfile --prefer-offline

COPY web/ ./
RUN pnpm build


FROM golang:1.25.13-bookworm AS go-build

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILT_AT=unknown

ENV CGO_ENABLED=0 \
    GO111MODULE=on \
    GOPROXY=https://proxy.golang.org,direct

WORKDIR /src

# Download modules before copying the rest of the source so this layer survives
# normal code changes. The cache mounts are used only during the build.
COPY go.mod go.sum ./
RUN --mount=type=cache,id=arca-go-mod,target=/go/pkg/mod \
    --mount=type=cache,id=arca-go-build,target=/root/.cache/go-build \
    go mod download

COPY . .
COPY --from=web-build /src/web/dist ./web/dist

RUN --mount=type=cache,id=arca-go-mod,target=/go/pkg/mod \
    --mount=type=cache,id=arca-go-build,target=/root/.cache/go-build \
    go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.builtAt=${BUILT_AT}" \
      -o /out/arca \
      ./cmd/arca

RUN mkdir -p /out-data


FROM gcr.io/distroless/static-debian12:nonroot AS runtime

ARG VERSION=dev

LABEL org.opencontainers.image.title="Arca" \
      org.opencontainers.image.description="Single-node self-hosted file vault" \
      org.opencontainers.image.version="${VERSION}"

COPY --from=go-build --chown=nonroot:nonroot /out/arca /arca
COPY --from=go-build --chown=nonroot:nonroot /out-data /data

# Arca creates config, SQLite, blobs, staging, previews, and locks below this
# directory. Mount a persistent volume here in every non-development deploy.
VOLUME ["/data"]

EXPOSE 8080

USER nonroot:nonroot

ENTRYPOINT ["/arca"]
CMD ["serve", "--listen", "0.0.0.0:8080", "--data-dir", "/data"]
