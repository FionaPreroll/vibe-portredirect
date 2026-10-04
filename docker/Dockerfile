# Images of portredirect_server and portredirect_client for Linux on amd64, arm64 and armv7,
# with the binaries that the release workflow builds and tests: on Debian with glibc, the
# default, or on Alpine with musl. The build context holds the binaries by platform and base
# image, see build-context.sh, which also shows how to build the images. The release workflow
# publishes them, see .github/workflows/release.yml.
#
# There is no RUN, so building the images for other platforms needs no emulation.

# debian or alpine.
ARG BASE=debian

FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a AS debian
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS alpine

FROM ${BASE} AS base
LABEL org.opencontainers.image.source="https://github.com/FionaPreroll/vibe-portredirect" \
      org.opencontainers.image.url="https://github.com/FionaPreroll/vibe-portredirect#docker" \
      org.opencontainers.image.licenses="GPL-3.0-only"
# The configuration directory, e.g. for the server's certificate and private key, is
# /etc/portredirect, instead of ~/.config/portredirect, as the user has no home directory.
ENV XDG_CONFIG_HOME=/etc
# A user of its own, without an entry in /etc/passwd, which the programs don't need. WORKDIR
# creates the configuration directory owned by it, and so does Docker for a new volume there.
USER 10001:10001
WORKDIR /etc/portredirect

FROM base AS server
ARG BASE
ARG TARGETPLATFORM
LABEL org.opencontainers.image.title="portredirect_server" \
      org.opencontainers.image.description="PortRedirect server: listens on the TCP ports its clients ask for and forwards the connections to them through a QUIC tunnel."
COPY ${TARGETPLATFORM}/${BASE}/portredirect_server /usr/local/bin/
# Keeps the certificate and private key when the container is created again, e.g. by Docker
# Compose, if no volume is given for them.
VOLUME /etc/portredirect
ENTRYPOINT ["/usr/local/bin/portredirect_server"]

FROM base AS client
ARG BASE
ARG TARGETPLATFORM
LABEL org.opencontainers.image.title="portredirect_client" \
      org.opencontainers.image.description="PortRedirect client: forwards the connections that the server accepts for it through a QUIC tunnel to a destination, e.g. another container."
COPY ${TARGETPLATFORM}/${BASE}/portredirect_client /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/portredirect_client"]
