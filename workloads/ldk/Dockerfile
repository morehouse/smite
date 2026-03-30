FROM debian:bookworm AS builder

# Build arguments
ARG LLVM_V=19
ARG BITCOIN_VERSION=29.2
ARG SCENARIO

ENV LLVM_V=${LLVM_V}

# Install LLVM toolchain (using modern key method without gnupg)
RUN apt-get update && apt-get install -y --no-install-recommends \
    software-properties-common \
    wget \
    ca-certificates
RUN mkdir -p /etc/apt/keyrings && \
    wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | tee /etc/apt/keyrings/llvm.asc > /dev/null && \
    echo "deb [signed-by=/etc/apt/keyrings/llvm.asc] http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-${LLVM_V} main" > /etc/apt/sources.list.d/llvm.list

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang-${LLVM_V} \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

ENV CC=clang-${LLVM_V}
ENV CXX=clang++-${LLVM_V}

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup install nightly && rustup default nightly

# Install cargo-afl for AFL instrumentation
RUN cargo install cargo-afl

# Download and install Bitcoin Core
WORKDIR /tmp
RUN wget https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz && \
    tar -xzf bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz && \
    mv bitcoin-${BITCOIN_VERSION}/bin/bitcoind /usr/local/bin/bitcoind && \
    mv bitcoin-${BITCOIN_VERSION}/bin/bitcoin-cli /usr/local/bin/bitcoin-cli && \
    rm -rf bitcoin-${BITCOIN_VERSION}*

# Build ldk-node-wrapper with AFL instrumentation.
# AFL_NO_CFG_FUZZING=1 prevents cargo-afl from setting --cfg fuzzing, which
# would enable simplified Poly1305 MAC in lightning's onion crypto and
# various test-only code paths. We want to fuzz the real production code.
WORKDIR /ldk-wrapper
COPY workloads/ldk/Cargo.toml workloads/ldk/Cargo.lock ./
COPY workloads/ldk/src/ src/
ENV AFL_NO_CFG_FUZZING=1
RUN cargo afl build --release

# Copy smite workspace files and build the Rust ldk-scenario binary
WORKDIR /smite
COPY Cargo.toml Cargo.lock ./
COPY smite/ smite/
COPY smite-scenarios/ smite-scenarios/
COPY smite-ir/ smite-ir/
COPY smite-nyx-sys/ smite-nyx-sys/
RUN TARGET_PATH=/ldk-wrapper/target/release/ldk-node-wrapper \
    cargo build -p smite-scenarios --bin ldk_${SCENARIO} --release --features nyx

# Build crash handler shared libraries, LD_PRELOADed into ldk-node-wrapper to
# report crashes immediately (before process teardown closes TCP sockets).
#   nyx-crash-handler.so  - reports crashes via Nyx hypercalls
#   crash-handler.so      - calls _exit(1), for local reproduction
RUN clang-${LLVM_V} -fPIC -DENABLE_NYX -DNO_PT_NYX -D_GNU_SOURCE \
    smite-nyx-sys/src/nyx-crash-handler.c -ldl -shared -o /nyx-crash-handler.so && \
    clang-${LLVM_V} -fPIC -D_GNU_SOURCE \
    smite-nyx-sys/src/nyx-crash-handler.c -ldl -shared -o /crash-handler.so

# Runtime image
FROM debian:bookworm-slim
ARG SCENARIO

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libstdc++6 \
    libgcc-s1 \
    && rm -rf /var/lib/apt/lists/*

# Copy ldk-node-wrapper binary and crash handlers
COPY --from=builder /ldk-wrapper/target/release/ldk-node-wrapper /usr/local/bin/ldk-node-wrapper
COPY --from=builder /nyx-crash-handler.so /crash-handler.so /

# Copy Bitcoin Core binaries
COPY --from=builder /usr/local/bin/bitcoind /usr/local/bin/bitcoind
COPY --from=builder /usr/local/bin/bitcoin-cli /usr/local/bin/bitcoin-cli

# Copy the ldk-scenario binary
COPY --from=builder /smite/target/release/ldk_${SCENARIO} /ldk-scenario

# Default to the local crash handler; init.sh overrides with the Nyx version.
ENV SMITE_CRASH_HANDLER=/crash-handler.so

# Copy the init script
COPY workloads/ldk/init.sh /init.sh
RUN chmod +x /init.sh /ldk-scenario

WORKDIR /
