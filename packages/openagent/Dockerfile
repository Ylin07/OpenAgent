FROM debian:bookworm-slim

# Disable the runtime transpiler cache by default inside Docker containers.
# On ephemeral containers, the cache is not useful.
ARG BUN_RUNTIME_TRANSPILER_CACHE_PATH=0
ENV BUN_RUNTIME_TRANSPILER_CACHE_PATH=${BUN_RUNTIME_TRANSPILER_CACHE_PATH}

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates libgcc-s1 libstdc++6 ripgrep \
  && rm -rf /var/lib/apt/lists/*

COPY dist/openagent-linux-x64/bin/openagent /usr/local/bin/openagent

RUN openagent --version
ENTRYPOINT ["openagent"]
