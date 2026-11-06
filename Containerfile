# Build and run the eBPF runtime.
#
# The build stage pins clang 19 because newer clang versions emit a
# memcpy extern that libbpf cannot resolve on the kernels tested here.

FROM archlinux:latest AS build

RUN pacman -Syu --noconfirm \
      base-devel \
      bpf \
      clang19 \
      libbpf \
      llvm19 \
      rustup

ENV PATH=/root/.cargo/bin:$PATH
RUN rustup toolchain install 1.95.0 --profile minimal --component rustfmt,clippy

WORKDIR /src
COPY . .
RUN cargo build --release -p runtime

FROM archlinux:latest

RUN mkdir -p /etc/ebpf-runtime

COPY --from=build /src/target/release/ebpf-runtime /usr/local/bin/ebpf-runtime
COPY rules /etc/ebpf-runtime/rules

WORKDIR /
ENTRYPOINT ["/usr/local/bin/ebpf-runtime"]
CMD ["run", "--rules", "/etc/ebpf-runtime/rules/default"]
