# syntax=docker/dockerfile:1
# run: --cap-add=SYS_PTRACE --security-opt seccomp=unconfined (DR needs both)

FROM ubuntu:24.04 AS builder

ARG DYNAMORIO_VERSION=11.91.20552
ARG RUST_VERSION=1.88.0

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain "${RUST_VERSION}" --profile minimal

RUN mkdir -p /opt/dynamorio && \
    curl -fSL "https://github.com/DynamoRIO/dynamorio/releases/download/cronbuild-${DYNAMORIO_VERSION}/DynamoRIO-Linux-${DYNAMORIO_VERSION}.tar.gz" \
    | tar -xzC /opt/dynamorio --strip-components=1 && \
    sed -i '/\(^if\|^elseif\)/s/\${\([^}]*\)}/\1/g' \
        /opt/dynamorio/drmemory/drmf/DrMemoryFrameworkConfig.cmake

WORKDIR /src
COPY CMakeLists.txt tracer.c memvis_bridge.h /src/
RUN cmake -B build -DCMAKE_BUILD_TYPE=Release \
        -DDynamoRIO_DIR=/opt/dynamorio/cmake && \
    cmake --build build -j"$(nproc)"

# dep pre-fetch: only invalidated by lockfile change
COPY engine/Cargo.toml engine/Cargo.lock /src/engine/
RUN mkdir -p /src/engine/src && \
    echo 'fn main(){}' > /src/engine/src/main.rs && \
    echo 'fn main(){}' > /src/engine/src/check.rs && \
    echo 'fn main(){}' > /src/engine/src/diff.rs && \
    echo 'fn main(){}' > /src/engine/src/lint.rs && \
    echo '' > /src/engine/src/lib.rs
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo build --release --manifest-path /src/engine/Cargo.toml 2>/dev/null || true

COPY engine/ /src/engine/
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo build --release --manifest-path /src/engine/Cargo.toml && \
    strip /src/engine/target/release/memvis \
          /src/engine/target/release/memvis-lint \
          /src/engine/target/release/memvis-diff \
          /src/engine/target/release/memvis-check

# minimal DR runtime tree: drrun + libs the tracer links
RUN mkdir -p /rt/dr/bin64 /rt/dr/lib64/release /rt/dr/ext/lib64/release && \
    cp /opt/dynamorio/bin64/drrun /rt/dr/bin64/ && \
    cp /opt/dynamorio/lib64/release/libdynamorio.so \
       /opt/dynamorio/lib64/release/libdrpreload.so /rt/dr/lib64/release/ && \
    cp /opt/dynamorio/ext/lib64/release/libdrmgr.so \
       /opt/dynamorio/ext/lib64/release/libdrutil.so \
       /opt/dynamorio/ext/lib64/release/libdrreg.so \
       /opt/dynamorio/ext/lib64/release/libdrwrap.so \
       /opt/dynamorio/ext/lib64/release/libdrsyms.so /rt/dr/ext/lib64/release/

FROM ubuntu:24.04 AS runtime

# zlib1g: runtime dep of libdrsyms.so
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates zlib1g \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -U -s /usr/sbin/nologin memvis

COPY --from=builder --chown=memvis:memvis /rt/dr /opt/dynamorio
COPY --from=builder --chown=memvis:memvis /src/build/libmemvis_tracer.so /app/
COPY --from=builder --chown=memvis:memvis \
    /src/engine/target/release/memvis \
    /src/engine/target/release/memvis-lint \
    /src/engine/target/release/memvis-diff \
    /src/engine/target/release/memvis-check \
    /usr/local/bin/

USER memvis
WORKDIR /app

ENV DYNAMORIO_HOME=/opt/dynamorio \
    MEMVIS_TRACER=/app/libmemvis_tracer.so \
    LD_LIBRARY_PATH=/opt/dynamorio/ext/lib64/release

STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/memvis"]