#!/bin/sh
# Local dev launcher for the FULL portal backend (com.pqc.PortalApplication).
#
# Why this script exists: running com.pqc.verify.VerifyApp (the narrowed
# verification scaffold) serves only the product/pricing/whitepaper/admin
# endpoints — the scanner, sandbox, and demo endpoints 404. The full app
# needs two things the defaults don't provide on this machine:
#
#   1. The JNI native lib — the pom default ../qudo-jni-crypto/build doesn't
#      exist next to this repo; the real build lives in ~/qudo-work.
#   2. The dev database — the qudo-verify-db docker container on 55432
#      (the local postgres on 5432 holds a stale pre-rework schema whose
#      Flyway history fails validation).
#
# PQC primitives are served by STOCK OpenSSL (homebrew openssl@3, 3.6.x —
# ML-KEM/ML-DSA/SLH-DSA are native since 3.5), selected with
# -Dqudo.provider.name=default. The Qudo provider is not required for the
# sandbox. To use it anyway: QUDO_PROVIDER_NAME=qudoprovider and point
# OPENSSL_MODULES at a dir containing qudoprovider.dylib (e.g.
# ~/qudo-work/qudo-provider-internal/build/lib).
#
# Deliberately launches java directly instead of `mvn spring-boot:run`:
# the plugin's forked JVM does not reliably inherit exported env vars.
#
# Prereq: docker container qudo-verify-db is running (55432 -> 5432).

set -e
cd "$(dirname "$0")"

QUDO_JNI_BUILD=${QUDO_JNI_BUILD:-$HOME/qudo-work/qudo-jni-crypto/build}
# FORCE the provider modules dir AND a neutral OpenSSL config — the shell
# profile on this Mac exports the QudoSSL dev install's environment:
#   OPENSSL_MODULES=/opt/qudossl/lib/ossl-modules   (no qudoprovider.dylib
#     there -> provider load fails with 0x7880025)
#   OPENSSL_CONF=/opt/qudossl/ssl/qudossl-fips.cnf  (default_properties =
#     fips=yes -> every EVP fetch in the JNI's libctx returns "unsupported")
# Use QUDO_MODULES_DIR / QUDO_OPENSSL_CONF to override deliberately.
export OPENSSL_MODULES=${QUDO_MODULES_DIR:-$HOME/qudo-work/qudo-provider-internal/build/lib}
export OPENSSL_CONF=${QUDO_OPENSSL_CONF:-/opt/homebrew/etc/openssl@3/openssl.cnf}

mvn -q compile dependency:build-classpath -Dmdep.outputFile=target/cp.txt

exec java \
  -Djava.library.path="$QUDO_JNI_BUILD" \
  -Dqudo.provider.name="${QUDO_PROVIDER_NAME:-qudoprovider}" \
  -Dspring.profiles.active=local \
  -Dspring.datasource.url="${SPRING_DATASOURCE_URL:-jdbc:postgresql://localhost:55432/qudo_portal}" \
  ${SERVER_PORT:+-Dserver.port=$SERVER_PORT} \
  -cp "target/classes:$(cat target/cp.txt)" \
  com.pqc.PortalApplication
