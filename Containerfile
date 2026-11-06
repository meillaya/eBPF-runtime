# Build the fleet binaries and dashboard.
#
# clang 19 is required: newer clang versions emit a memcpy extern that libbpf
# cannot resolve on the kernels tested here.

FROM oven/bun:1 AS web
WORKDIR /web
# The dashboard reads these at build time. Empty keeps the dev-auth badge;
# the OIDC test profile passes its Dex issuer and public client id.
ARG VITE_OIDC_ISSUER=""
ARG VITE_OIDC_CLIENT_ID=""
ENV VITE_OIDC_ISSUER=$VITE_OIDC_ISSUER
ENV VITE_OIDC_CLIENT_ID=$VITE_OIDC_CLIENT_ID
COPY web/package.json web/bun.lock ./
RUN bun install --frozen-lockfile
COPY web/ ./
# The policy editor can load the canonical default pack. The source import
# resolves to /rules inside this stage, matching the relative path used by
# the local Vite build.
COPY rules /rules
RUN bun run build

FROM archlinux:latest AS build
RUN pacman -Syu --noconfirm \
      base-devel \
      bpf \
      clang19 \
      elfutils \
      libbpf \
      llvm19 \
      openssl \
      librdkafka \
      rustup \
      zlib
ENV PATH=/root/.cargo/bin:$PATH
ENV CLANG=/usr/bin/clang-19
RUN rustup toolchain install 1.95.0 --profile minimal --component rustfmt,clippy
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release \
      -p agent \
      -p bench \
      -p control-plane \
      -p relay \
      -p cli \
      -p runtime \
    && mkdir -p /out \
    && cp target/release/ebpf-agent \
          target/release/ebpf-control-plane \
          target/release/ebpf-relay \
          target/release/ebpfctl \
          target/release/ebpf-runtime \
          target/release/ebpf-bench \
          /out/

FROM archlinux:latest AS runtime
RUN pacman -Syu --noconfirm \
      ca-certificates \
      libbpf \
      openssl \
      librdkafka \
      zlib \
    && rm -rf /var/cache/pacman/pkg/*
RUN mkdir -p /etc/ebpf-agent /etc/ebpf-control-plane /var/lib/ebpf-agent /usr/share/ebpf/web
COPY --from=build /out/ebpf-agent /usr/local/bin/ebpf-agent
COPY --from=build /out/ebpf-control-plane /usr/local/bin/ebpf-control-plane
COPY --from=build /out/ebpf-relay /usr/local/bin/ebpf-relay
COPY --from=build /out/ebpfctl /usr/local/bin/ebpfctl
COPY --from=build /out/ebpf-runtime /usr/local/bin/ebpf-runtime
COPY --from=build /out/ebpf-bench /usr/local/bin/ebpf-bench
COPY --from=web /web/dist /usr/share/ebpf/web
COPY rules /etc/ebpf-runtime/rules
WORKDIR /
ENTRYPOINT ["/usr/local/bin/ebpf-agent"]
CMD ["run", "--config", "/etc/ebpf-agent/agent.toml"]
