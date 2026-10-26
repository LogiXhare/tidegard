# syntax=docker/dockerfile:1
#
# Tidegard service images (ADR 0052). The build context is an
# unpacked release tarball, so each image holds exactly the binaries the
# tarball ships. One target per service:
#
#   docker build -f deployments/docker/Dockerfile --target collector \
#     --build-arg VERSION=<version> -t tidegard-collector \
#     tidegard-<version>-linux-<arch>/
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

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2 AS base
ARG VERSION=0.0.0
LABEL org.opencontainers.image.source="https://github.com/LogiXhare/tidegard" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="WeTechi Solutions" \
      org.opencontainers.image.version="${VERSION}"
COPY LICENSE NOTICE THIRD-PARTY-NOTICES.txt THIRD-PARTY-NOTICES-WEB.txt /usr/share/doc/tidegard/
# Numeric, so a runtime can verify it is not root (runAsNonRoot).
USER 65532:65532

FROM base AS collector
LABEL org.opencontainers.image.title="tidegard-collector"
COPY bin/tidegard-collector /usr/local/bin/
ENV TIDEGARD_COLLECTOR_METRICS_BIND=0.0.0.0:9090
EXPOSE 2055/udp 9090/tcp
ENTRYPOINT ["/usr/local/bin/tidegard-collector"]

FROM base AS incident-manager
LABEL org.opencontainers.image.title="tidegard-incident-manager"
COPY bin/tidegard-incident-manager /usr/local/bin/
ENV TIDEGARD_INCIDENT_METRICS_BIND=0.0.0.0:9091
EXPOSE 9091/tcp
ENTRYPOINT ["/usr/local/bin/tidegard-incident-manager"]

FROM base AS api
LABEL org.opencontainers.image.title="tidegard-api"
COPY bin/tidegard-api bin/tidegardctl /usr/local/bin/
COPY share/web /usr/share/tidegard/web
ENV TIDEGARD_API_WEB_ROOT=/usr/share/tidegard/web
EXPOSE 8080/tcp
ENTRYPOINT ["/usr/local/bin/tidegard-api"]

FROM base AS notifier
LABEL org.opencontainers.image.title="tidegard-notifier"
COPY bin/tidegard-notifier /usr/local/bin/
ENV TIDEGARD_NOTIFY_METRICS_BIND=0.0.0.0:9093
EXPOSE 9093/tcp
ENTRYPOINT ["/usr/local/bin/tidegard-notifier"]

FROM base AS mitigator
LABEL org.opencontainers.image.title="tidegard-mitigator"
COPY bin/tidegard-mitigator /usr/local/bin/
ENV TIDEGARD_MITIGATOR_METRICS_BIND=0.0.0.0:9094
EXPOSE 9094/tcp
ENTRYPOINT ["/usr/local/bin/tidegard-mitigator"]
