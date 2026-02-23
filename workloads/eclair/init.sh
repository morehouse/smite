#!/bin/sh

# This script is executed inside the VM by the Nyx fuzzer

set -eu

# Run the Eclair fuzzing harness
export SMITE_NYX=1
export JAVA_HOME=/opt/java/openjdk
export PATH=$PATH:/usr/local/bin:/opt/eclair/bin:$JAVA_HOME/bin

# Inject the coverage agent. JAVA_OPTS is picked up by eclair-node.sh and
# passed to the JVM.
export JAVA_OPTS="-javaagent:/eclair-sancov.jar -Djava.library.path=/usr/local/lib"

/eclair-scenario > /init.log 2>&1
