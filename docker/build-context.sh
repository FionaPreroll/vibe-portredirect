#!/usr/bin/env bash
# Prepares the build context for docker/Dockerfile: the binaries from the release archives,
# portredirect-linux-<arch>[-musl].tar.gz, by platform and base image, e.g.
# linux/arm/v7/debian/portredirect_client from portredirect-linux-armv7.tar.gz and
# linux/arm/v7/alpine/portredirect_client from portredirect-linux-armv7-musl.tar.gz.
#
# Usage: docker/build-context.sh <directory with the archives> <context directory>
#
# Then, e.g. for the client on Alpine:
#
#   docker buildx build --file docker/Dockerfile --target client --build-arg BASE=alpine \
#     --platform linux/amd64,linux/arm64,linux/arm/v7 <context directory>
#
# The archives come from the pre-release "latest" or from the release workflow's run.
set -euo pipefail

archives=$1
context=$2
extracted=$(mktemp -d)
trap 'rm -rf "$extracted"' EXIT

for arch in amd64 arm64 armv7; do
    case $arch in
    amd64) platform=linux/amd64 ;;
    arm64) platform=linux/arm64 ;;
    armv7) platform=linux/arm/v7 ;;
    esac
    for base in debian alpine; do
        name=portredirect-linux-$arch
        if [ "$base" = alpine ]; then
            name=$name-musl
        fi
        tar --extract --gzip --file "$archives/$name.tar.gz" --directory "$extracted"
        mkdir -p "$context/$platform/$base"
        cp "$extracted/$name/portredirect_server" "$extracted/$name/portredirect_client" \
            "$context/$platform/$base/"
    done
done
