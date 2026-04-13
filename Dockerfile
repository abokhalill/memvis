# syntax=docker/dockerfile:1

FROM ubuntu:22.04 AS builder

ARG DYNAMORIO_VERSION=11.91.20552
ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable --profile minimal \
    && rustup component add clippy

RUN mkdir -p /opt/dynamorio && \
    curl -fSL "https://github.com/DynamoRIO/dynamorio/releases/download/cronbuild-${DYNAMORIO_VERSION}/DynamoRIO-Linux-${DYNAMORIO_VERSION}.tar.gz" \
    | tar -xzC /opt/dynamorio --strip-components=1 && \
    sed -i '/\(^if\|^elseif\)/s/\${\([^}]*\)}/\1/g' \
        /opt/dynamorio/drmemory/drmf/DrMemoryFrameworkConfig.cmake

WORKDIR /src

COPY CMakeLists.txt tracer.c memvis_bridge.h /src/
RUN mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release -DDynamoRIO_DIR=/opt/dynamorio/cmake .. && \
    make -j$(nproc)

COPY engine/ /src/engine/
WORKDIR /src/engine
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/engine/target \
    cargo clippy --release -- -D warnings && \
    cargo build --release && \
    cp target/release/memvis /usr/local/bin/memvis

RUN mkdir -p /rt/dist/dr/bin64 \
             /rt/dist/dr/lib64/release \
             /rt/dist/dr/ext/lib64/release && \
    cp /opt/dynamorio/bin64/drrun /rt/dist/dr/bin64/ && \
    cp /opt/dynamorio/lib64/release/libdynamorio.so \
       /opt/dynamorio/lib64/release/libdrpreload.so /rt/dist/dr/lib64/release/ && \
    cp /opt/dynamorio/ext/lib64/release/libdrmgr.so \
       /opt/dynamorio/ext/lib64/release/libdrutil.so \
       /opt/dynamorio/ext/lib64/release/libdrreg.so /rt/dist/dr/ext/lib64/release/

# ---------------------------------------------------------------------------
FROM ubuntu:22.04 AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* && \
    useradd -m -U memvis

USER memvis
WORKDIR /app

COPY --from=builder --chown=memvis:memvis /rt/dist/dr /opt/dynamorio
COPY --from=builder --chown=memvis:memvis /src/build/libmemvis_tracer.so /app/
COPY --from=builder --chown=memvis:memvis /usr/local/bin/memvis /usr/local/bin/

ENV DYNAMORIO_HOME=/opt/dynamorio \
    MEMVIS_TRACER=/app/libmemvis_tracer.so \
    LD_LIBRARY_PATH="/opt/dynamorio/ext/lib64/release${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/memvis"]