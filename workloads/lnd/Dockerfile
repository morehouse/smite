FROM debian:bookworm AS builder

# Build arguments
ARG LLVM_V=19
ARG GO_VERSION=1.24.11
ARG LND_VERSION=v0.20.0-beta
ARG BITCOIN_VERSION=29.2

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

# Install Go
RUN wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
    rm go${GO_VERSION}.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"
ENV PATH="${GOPATH}/bin:${PATH}"

# Copy smite source
WORKDIR /smite
COPY . .

# Clone LND
RUN git clone --depth 1 --branch ${LND_VERSION} https://github.com/lightningnetwork/lnd.git /lnd

WORKDIR /lnd

# Apply coverage patch and build LND with coverage instrumentation
RUN git apply /smite/workloads/lnd/0001-sancov.patch
RUN cd cmd/lnd && CGO_ENABLED=1 go build -v -tags=libfuzzer -gcflags=all=-d=libfuzzer
RUN cd cmd/lncli && go build

# Download and install Bitcoin Core
WORKDIR /tmp
RUN wget https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz && \
    tar -xzf bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz && \
    mv bitcoin-${BITCOIN_VERSION}/bin/bitcoind /usr/local/bin/bitcoind && \
    mv bitcoin-${BITCOIN_VERSION}/bin/bitcoin-cli /usr/local/bin/bitcoin-cli && \
    rm -rf bitcoin-${BITCOIN_VERSION}*

# Build smite-nyx-sys with correct coverage map size
WORKDIR /smite
RUN TARGET_PATH=/lnd/cmd/lnd/lnd cargo build -p smite-nyx-sys --release

# Build the lnd-scenario fuzzing harness with nyx support
WORKDIR /smite/workloads/lnd/lnd-scenario
RUN CGO_ENABLED=1 go build -v -tags=nyx -o /lnd-scenario

# Runtime image
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libstdc++6 \
    libgcc-s1 \
    && rm -rf /var/lib/apt/lists/*

# Copy the nyx agent library
COPY --from=builder /smite/target/release/libnyx_agent.so /usr/local/lib/libnyx_agent.so

# Register the library with the dynamic linker
RUN ldconfig

# Copy LND binaries
COPY --from=builder /lnd/cmd/lnd/lnd /usr/local/bin/lnd
COPY --from=builder /lnd/cmd/lncli/lncli /usr/local/bin/lncli

# Copy Bitcoin Core binaries
COPY --from=builder /usr/local/bin/bitcoind /usr/local/bin/bitcoind
COPY --from=builder /usr/local/bin/bitcoin-cli /usr/local/bin/bitcoin-cli

# Copy the lnd-scenario binary
COPY --from=builder /lnd-scenario /lnd-scenario

# Copy the init script
COPY ./workloads/lnd/init.sh /init.sh
RUN chmod +x /init.sh /lnd-scenario

WORKDIR /
