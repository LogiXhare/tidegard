# syntax=docker/dockerfile:1
#
# WetechiNetMon service images (ADR 0052). The build context is an
# unpacked release tarball, so each image holds exactly the binaries the
# tarball ships. One target per service:
#
#   docker build -f deployments/docker/Dockerfile --target collector \
#     --build-arg VERSION=<version> -t wetechinetmon-collector \
#     wetechinetmon-<version>-linux-<arch>/
#
# The base is distroless cc on Debian 13: glibc and CA certificates, no
# shell and no package manager. It is pinned by digest, and Dependabot
# proposes updates. Every image runs as distroless's nonroot user (65532)
# and works with a read-only root filesystem.
#
# Inside a container, the metrics address listens on all interfaces so a
# probe or Prometheus can reach it; publishing decides who can. The API
# keeps its loopback default: off loopback it needs TLS (ADR 0038), which
# the deployment configures.

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:54df941ed0d06a1bd95ef5e0ce391fd8d9f94b64782dc9a60062727849ee3f97 AS base
ARG VERSION=0.0.0
LABEL org.opencontainers.image.source="https://github.com/LogiXhare/wetechi-netmon" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="WeTechi Solutions" \
      org.opencontainers.image.version="${VERSION}"
COPY LICENSE NOTICE /usr/share/doc/wetechinetmon/
USER nonroot:nonroot

FROM base AS collector
LABEL org.opencontainers.image.title="wetechinetmon-collector"
COPY bin/wetechinetmon-collector /usr/local/bin/
ENV WETECHINETMON_COLLECTOR_METRICS_BIND=0.0.0.0:9090
EXPOSE 2055/udp 9090/tcp
ENTRYPOINT ["/usr/local/bin/wetechinetmon-collector"]

FROM base AS incident-manager
LABEL org.opencontainers.image.title="wetechinetmon-incident-manager"
COPY bin/wetechinetmon-incident-manager /usr/local/bin/
ENV WETECHINETMON_INCIDENT_METRICS_BIND=0.0.0.0:9091
EXPOSE 9091/tcp
ENTRYPOINT ["/usr/local/bin/wetechinetmon-incident-manager"]

FROM base AS api
LABEL org.opencontainers.image.title="wetechinetmon-api"
COPY bin/wetechinetmon-api bin/wetechinetmonctl /usr/local/bin/
COPY share/web /usr/share/wetechinetmon/web
ENV WETECHINETMON_API_WEB_ROOT=/usr/share/wetechinetmon/web
EXPOSE 8080/tcp
ENTRYPOINT ["/usr/local/bin/wetechinetmon-api"]

FROM base AS notifier
LABEL org.opencontainers.image.title="wetechinetmon-notifier"
COPY bin/wetechinetmon-notifier /usr/local/bin/
ENV WETECHINETMON_NOTIFY_METRICS_BIND=0.0.0.0:9093
EXPOSE 9093/tcp
ENTRYPOINT ["/usr/local/bin/wetechinetmon-notifier"]

FROM base AS mitigator
LABEL org.opencontainers.image.title="wetechinetmon-mitigator"
COPY bin/wetechinetmon-mitigator /usr/local/bin/
ENV WETECHINETMON_MITIGATOR_METRICS_BIND=0.0.0.0:9094
EXPOSE 9094/tcp
ENTRYPOINT ["/usr/local/bin/wetechinetmon-mitigator"]
