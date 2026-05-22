# syntax=docker/dockerfile:1.7
#
# Self-contained, multi-stage build for the Qudo PQC Portal backend.
# DevOps runs `docker build -t qudo-portal-backend:1.0.0 .` and gets a
# production-shape image — no external base images, no separate runtime
# build step, no private registry.
#
# Build stages:
#   1. openssl-build  — compile OpenSSL 3.5 from source (public distros
#                       still ship 3.0; we need ≥3.4 for the Qudo
#                       provider + PQC TLS groups in the scanner)
#   2. jar-build      — Maven + JDK 17, install the bundled qudo-jni-
#                       crypto artifact, package the Spring Boot fat JAR
#   3. runtime        — eclipse-temurin JRE + OpenSSL from stage 1 + the
#                       Qudo native libs + the JAR, running as a non-
#                       root user with a Spring Actuator HEALTHCHECK.
#
# Native libs prerequisite — DevOps must drop the Linux build of the
# Qudo JNI crypto + provider into:
#     libs/native/linux-x86_64/libqudo_jni_crypto.so
#     libs/native/linux-x86_64/qudoprovider.so
# (Build them once from the qudo-jni-crypto repo; see its README. The
# macOS .dylib in this repo's libs/ is for local dev only.)

# ─────────────────────────────────────────────────────────────────────
# Stage 1 — Build OpenSSL 3.5 from source.
#
# Base image matches the runtime base (eclipse-temurin:17-jre-jammy is
# Ubuntu 22.04) so glibc + libssl symbol versions line up. If the build
# base is newer than the runtime base, the resulting openssl binary
# falls back to the runtime's system libssl/libcrypto and gets
# "version `OPENSSL_3.x.0' not found" at startup.
#
# `-Wl,-rpath,/opt/openssl/lib64` bakes an RPATH into every binary so
# they self-reference the bundled libs regardless of LD_LIBRARY_PATH.
# Belt-and-braces against accidental LD_LIBRARY_PATH unset.
#
# Cached aggressively: as long as OPENSSL_VERSION doesn't change,
# subsequent `docker build` invocations skip this entire stage.
# ─────────────────────────────────────────────────────────────────────
FROM ubuntu:22.04 AS openssl-build

ARG OPENSSL_VERSION=3.5.0

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential \
      wget \
      perl \
      ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /tmp
RUN wget -q "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz" && \
    tar xzf "openssl-${OPENSSL_VERSION}.tar.gz" && \
    cd "openssl-${OPENSSL_VERSION}" && \
    ./config --prefix=/opt/openssl --openssldir=/opt/openssl/ssl \
        -Wl,-rpath,/opt/openssl/lib64 \
        shared no-tests no-docs && \
    make -j"$(nproc)" && \
    make install_sw && \
    rm -rf /tmp/openssl-*

# ─────────────────────────────────────────────────────────────────────
# Stage 2 — Build the Spring Boot fat JAR.
# ─────────────────────────────────────────────────────────────────────
FROM maven:3.9-eclipse-temurin-17 AS jar-build

WORKDIR /app

# The Qudo JNI crypto artifact isn't on Maven Central; install the
# bundled copy into this stage's local repo so the pom's
# <dependency>com.qudo:qudo-jni-crypto:1.0.0</dependency> resolves.
COPY libs/qudo-jni-crypto-1.0.0.jar /tmp/qudo-jni.jar
COPY libs/qudo-jni-crypto-1.0.0.pom /tmp/qudo-jni.pom
RUN mvn install:install-file \
      -Dfile=/tmp/qudo-jni.jar \
      -DpomFile=/tmp/qudo-jni.pom \
      -DgroupId=com.qudo \
      -DartifactId=qudo-jni-crypto \
      -Dversion=1.0.0 \
      -Dpackaging=jar \
      -q

# Copy pom + go-offline first so the dep layer caches between builds.
COPY pom.xml .
RUN mvn dependency:go-offline -B 2>/dev/null || true

COPY src ./src
RUN mvn package -DskipTests -B

# ─────────────────────────────────────────────────────────────────────
# Stage 3 — Runtime image.
# JRE 17 + OpenSSL 3.5 + Qudo native libs + the built JAR.
# ─────────────────────────────────────────────────────────────────────
FROM eclipse-temurin:17-jre-jammy AS runtime

LABEL org.opencontainers.image.title="Qudo PQC Portal Backend" \
      org.opencontainers.image.description="Spring Boot backend for the Qudo PQC Developer Portal" \
      org.opencontainers.image.vendor="ZenV Quantum" \
      org.opencontainers.image.source="https://github.com/ZenVInnovations/qudo-portal-backend"

# curl is used by the HEALTHCHECK; ca-certificates are needed for any
# outbound HTTPS (e.g. the scanner probing external endpoints).
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      curl \
      ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# OpenSSL 3.5 from stage 1 — replaces the system openssl on PATH.
# LD_LIBRARY_PATH covers both `lib` and `lib64` because OpenSSL's
# installer puts shared libs in `lib` on Ubuntu (Debian convention)
# but `lib64` on RHEL-family distros. Listing both is harmless and
# avoids surprises if the build base ever changes.
COPY --from=openssl-build /opt/openssl /opt/openssl
ENV PATH=/opt/openssl/bin:$PATH \
    LD_LIBRARY_PATH=/opt/openssl/lib:/opt/openssl/lib64

# Qudo native artifacts.
#   - libqudo_jni_crypto.so  → loaded by Spring Boot via -Djava.library.path
#   - qudoprovider.so        → loaded by OpenSSL as a provider plugin
# Provider lands in /opt/openssl/lib/ossl-modules/ alongside engines-3
# (the path OpenSSL's loader actually scans on Ubuntu).
# These must be Linux x86_64 builds; see the native libs prerequisite
# note at the top of this Dockerfile.
COPY libs/native/linux-x86_64/libqudo_jni_crypto.so /app/lib/
COPY libs/native/linux-x86_64/qudoprovider.so /opt/openssl/lib/ossl-modules/

# Non-root user — the JVM never needs root, and dropping privileges
# limits the blast radius of any RCE in the app or a dependency.
RUN useradd --system --uid 1000 --create-home --home-dir /home/qudo qudo && \
    mkdir -p /var/lib/qudo /app && \
    chown -R qudo:qudo /var/lib/qudo /app /home/qudo

WORKDIR /app
COPY --from=jar-build --chown=qudo:qudo /app/target/*.jar app.jar

USER qudo

# Spring Boot prod profile listens on 8093 (see application-prod.yml).
EXPOSE 8093

# Spring Actuator /health is exposed unauthenticated on the prod
# profile. start-period gives the JVM time to warm up + load the JNI
# library before health is first probed.
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -fsS http://localhost:8093/actuator/health || exit 1

# Default to the prod profile so the container behaves like production
# out of the box. Override at runtime with `-e SPRING_PROFILES_ACTIVE=dev`.
ENV SPRING_PROFILES_ACTIVE=prod \
    JAVA_OPTS=""

# JAVA_OPTS is passed through so DevOps can tune heap / GC / debug flags
# at deploy time without rebuilding the image:
#   docker run -e JAVA_OPTS="-Xmx512m -XX:MaxRAMPercentage=75" ...
ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -Djava.library.path=/app/lib -jar app.jar"]
