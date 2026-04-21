#!/usr/bin/env bash
#
# DISABLED (supply-chain, HIGH-11): the original script pulled a zip over
# plaintext HTTP from noah.lampac.sh with TLS verification explicitly
# skipped (`curl -k`), then unzipped it on top of /home without any
# authenticity check. That is an arbitrary-code-execution vector for
# anyone on-path between the container host and noah.lampac.sh.
#
# This file is kept only for upstream compatibility (so `git merge` from
# immisterio/lampac does not conflict). It is no longer invoked from any
# Dockerfile in this fork. If you need the upstream hot-patch behaviour,
# fetch a pinned HTTPS URL and verify a SHA-256 before unzipping.
#
# Refuse to run by default — fail closed.
echo "update.sh is disabled in this fork (supply-chain hardening). See file header." >&2
exit 1
