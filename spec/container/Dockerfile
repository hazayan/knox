ARG java_runtime
ARG java_version

FROM ghcr.io/${java_runtime}:${java_version}

RUN microdnf install -y wget

RUN mkdir -p /usr/local/bin
COPY tla.sh /usr/local/bin/

WORKDIR /tools

ARG tla_hash
ARG tla_version

RUN wget \
    "https://github.com/tlaplus/tlaplus/releases/download/v${tla_version}/tla2tools.jar" && \
    echo "${tla_hash} tla2tools.jar" | sha1sum --check --status


ENTRYPOINT ["/usr/local/bin/tla.sh"]

