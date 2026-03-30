# eclipse-temurin:21 provides JDK 21
FROM eclipse-temurin:21 AS builder

# Build arguments
ARG ECLAIR_VERSION=v0.13.1
ARG BITCOIN_VERSION=29.2
ARG SCENARIO

# Install build dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    maven \
    unzip \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Download and install Bitcoin Core
WORKDIR /tmp
RUN wget https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz && \
    tar -xzf bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz && \
    mv bitcoin-${BITCOIN_VERSION}/bin/bitcoind /usr/local/bin/bitcoind && \
    mv bitcoin-${BITCOIN_VERSION}/bin/bitcoin-cli /usr/local/bin/bitcoin-cli && \
    rm -rf bitcoin-${BITCOIN_VERSION}*

# Clone and build Eclair.
RUN git clone --depth 1 --branch ${ECLAIR_VERSION} https://github.com/ACINQ/eclair.git /eclair-src
WORKDIR /eclair-src
RUN ./mvnw package -DskipTests -pl eclair-node -am

# Unzip the Eclair distribution to /opt/eclair/.
# /opt/ is used instead of /usr/local/ because eclair-node.sh uses relative
# paths (../lib/) to locate its JARs; splitting bin/ from lib/ would break it.
RUN find eclair-node/target -name "eclair-node-*-bin.zip" \
        -exec unzip {} -d /opt \; && \
    mv /opt/eclair-node-* /opt/eclair

# Build the eclair-sancov Java agent.
COPY workloads/eclair/eclair-sancov/ /eclair-sancov/
WORKDIR /eclair-sancov
RUN mvn package

# Compile the JNI shared library that maps the AFL shared memory segment.
# JAVA_HOME is set by the eclipse-temurin base image.
RUN cc -shared -fPIC \
    -I"${JAVA_HOME}/include" \
    -I"${JAVA_HOME}/include/linux" \
    src/main/c/shmutil.c \
    -o /usr/local/lib/libeclair-sancov.so

# Count instrumentable Eclair methods to determine TARGET_MAP_SIZE.
# EclairEdgeCounter scans the same fr/acinq/eclair/ methods that
# EclairTransformer will instrument, so the count matches exactly.
RUN java -cp target/eclair-sancov-0.0.0.jar EclairEdgeCounter \
    $(find /opt/eclair/lib -name "*.jar" | tr '\n' ' ') \
    > /tmp/eclair-edge-count.txt && \
    echo "Eclair edge count: $(cat /tmp/eclair-edge-count.txt)"

# Copy smite workspace and build the eclair scenario binary.
WORKDIR /smite
COPY Cargo.toml Cargo.lock ./
COPY smite/ smite/
COPY smite-scenarios/ smite-scenarios/
COPY smite-ir/ smite-ir/
COPY smite-nyx-sys/ smite-nyx-sys/
RUN TARGET_MAP_SIZE=$(cat /tmp/eclair-edge-count.txt) \
    cargo build -p smite-scenarios --bin eclair_${SCENARIO} --release --features nyx

# Build JVM crash handler shared libraries, LD_PRELOADed into the JVM to
# report crashes before atexit handlers close TCP sockets. Two variants:
#   nyx-jvm-crash-handler.so - reports crashes via Nyx hypercalls
#   jvm-crash-handler.so     - writes /tmp/smite-crash.log for local mode
RUN cc -shared -fPIC -DENABLE_NYX -DNO_PT_NYX \
    smite-nyx-sys/src/jvm-crash-handler.c -o /nyx-jvm-crash-handler.so && \
    cc -shared -fPIC \
    smite-nyx-sys/src/jvm-crash-handler.c -o /jvm-crash-handler.so

# Runtime image.
FROM eclipse-temurin:21-jre
ARG SCENARIO

# Install curl for Eclair readiness polling in EclairTarget::query_info().
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy Eclair distribution (bin/eclair-node.sh + lib/*.jar)
COPY --from=builder /opt/eclair /opt/eclair

# Copy Bitcoin Core binaries
COPY --from=builder /usr/local/bin/bitcoind /usr/local/bin/bitcoind
COPY --from=builder /usr/local/bin/bitcoin-cli /usr/local/bin/bitcoin-cli

# Copy coverage agent and JNI shared library
COPY --from=builder /eclair-sancov/target/eclair-sancov-0.0.0.jar /eclair-sancov.jar
COPY --from=builder /usr/local/lib/libeclair-sancov.so /usr/local/lib/libeclair-sancov.so

# Copy crash handlers and eclair scenario binary
COPY --from=builder /nyx-jvm-crash-handler.so /jvm-crash-handler.so /
COPY --from=builder /smite/target/release/eclair_${SCENARIO} /eclair-scenario

# Default to the local crash handler; init.sh overrides with the Nyx version.
ENV SMITE_CRASH_HANDLER=/jvm-crash-handler.so

# Install a java wrapper that LD_PRELOADs the crash handler on the JVM only.
# eclair-node.sh runs shell commands (ls, grep, awk) that would inherit
# LD_PRELOAD and trigger false crash reports when they exit(0). The wrapper
# ensures only the JVM process gets the crash handler.
RUN mv "$JAVA_HOME/bin/java" "$JAVA_HOME/bin/java.real" && \
    printf '#!/bin/sh\nLD_PRELOAD=$SMITE_CRASH_HANDLER exec %s/bin/java.real "$@"\n' \
        "$JAVA_HOME" > "$JAVA_HOME/bin/java" && \
    chmod +x "$JAVA_HOME/bin/java"

# Copy init script
COPY workloads/eclair/init.sh /init.sh
RUN chmod +x /init.sh /eclair-scenario

ENV PATH="/opt/eclair/bin:${PATH}"

WORKDIR /
