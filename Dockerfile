# =============================================================================
# Qudo Portal Backend — self-contained image for Docker / Kubernetes
# -----------------------------------------------------------------------------
# Three stages:
#   1. openssl-build  — compile OpenSSL 3.5 from source (Ubuntu's 3.0 is too
#                       old for qudoprovider.so, which needs OpenSSL >= 3.3).
#                       Slow first build (~5 min); cached afterwards.
#   2. maven-build    — install qudo-jni-crypto into local Maven repo,
#                       build the Spring Boot fat jar.
#   3. runtime        — JRE 17 + OpenSSL 3.5 + native .so files + jar,
#                       all baked in. No external base image, no volume
#                       mounts required at runtime.
# =============================================================================

# ----- Stage 1: OpenSSL 3.5 builder ------------------------------------------
FROM eclipse-temurin:17-jre AS openssl-build

ARG OPENSSL_VERSION=3.5.0

RUN apt-get update && apt-get install -y --no-install-recommends \
        wget build-essential ca-certificates perl \
    && cd /tmp \
    && wget -q https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz \
    && tar -xzf openssl-${OPENSSL_VERSION}.tar.gz \
    && cd openssl-${OPENSSL_VERSION} \
    && ./Configure --prefix=/usr/local/openssl --openssldir=/usr/local/openssl/ssl \
       shared no-tests \
    && make -j"$(nproc)" -s \
    && make install_sw install_ssldirs -s \
    && rm -rf /tmp/openssl*

# ----- Stage 2: Maven builder ------------------------------------------------
FROM maven:3.9-eclipse-temurin-17 AS maven-build
WORKDIR /build

# Install the qudo-jni-crypto jar into the local Maven repo so pom.xml's
# <dependency> resolves. Same one-time install that the README documents.
COPY libs/qudo-jni-crypto-1.0.0.jar /tmp/qudo-jni.jar
COPY libs/qudo-jni-crypto-1.0.0.pom /tmp/qudo-jni.pom
RUN mvn install:install-file -Dfile=/tmp/qudo-jni.jar -DpomFile=/tmp/qudo-jni.pom \
        -DgroupId=com.qudo -DartifactId=qudo-jni-crypto -Dversion=1.0.0 -Dpackaging=jar -q

# Pre-fetch deps so source-only changes don't re-download the world.
COPY pom.xml .
RUN mvn -B -q dependency:go-offline || true

COPY src ./src
RUN mvn -B -q package -DskipTests

# ----- Stage 3: Runtime ------------------------------------------------------
FROM eclipse-temurin:17-jre

# curl   — for `kubectl exec` debugging and any healthchecks
# patchelf — clear the executable-stack flag on libqudo-pqc.so (released
#            without -Wl,-z,noexecstack; newer glibc refuses to dlopen
#            libraries that request +X stack)
RUN apt-get update && apt-get install -y --no-install-recommends curl patchelf \
    && rm -rf /var/lib/apt/lists/*

# OpenSSL 3.5 from stage 1.
COPY --from=openssl-build /usr/local/openssl /usr/local/openssl

# Link the isolated OpenSSL's CA dir to the system CA bundle so TLS
# verification works for outbound calls (SMTP STARTTLS, scanner).
RUN mkdir -p /usr/local/openssl/ssl/certs \
    && ln -sf /etc/ssl/certs/ca-certificates.crt /usr/local/openssl/ssl/cert.pem

# Three Linux native libs that the JNI provider needs:
#   libqudo_jni_crypto.so  — System.loadLibrary("qudo_jni_crypto") target
#   libqudo-pqc.so         — crypto module the JNI links against
#   qudoprovider.so        — OpenSSL 3 provider plugin (PQC algorithms)
WORKDIR /app
RUN mkdir -p /app/lib /app/keys
COPY docker/native/libqudo_jni_crypto.so /app/lib/
COPY docker/native/libqudo-pqc.so        /app/lib/
COPY docker/native/qudoprovider.so       /app/lib/

# Defensive: ensure none of the .so files request an executable stack.
# Idempotent — no-op when the flag is already clear.
RUN patchelf --clear-execstack /app/lib/libqudo_jni_crypto.so \
                                /app/lib/libqudo-pqc.so \
                                /app/lib/qudoprovider.so

# The dynamic linker needs OpenSSL 3.5's libcrypto.so.3 first, then the
# JNI libs. OPENSSL_MODULES tells OpenSSL where to look for provider
# plugins (qudoprovider.so).
ENV LD_LIBRARY_PATH=/usr/local/openssl/lib64:/app/lib \
    OPENSSL_MODULES=/app/lib \
    PATH=/usr/local/openssl/bin:$PATH \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    SSL_CERT_DIR=/etc/ssl/certs

COPY --from=maven-build /build/target/qudo-portal-backend-*.jar /app/app.jar

EXPOSE 8093

# -Djava.library.path so System.loadLibrary("qudo_jni_crypto") resolves
# without falling back to the JAR-bundled .dylib (macOS-only) extract path.
ENTRYPOINT ["java", "-Djava.library.path=/app/lib", "-jar", "/app/app.jar"]
