FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /app

# Install the bundled Qudo JNI artifact into the local Maven repo so the
# pom.xml's <dependency> resolves. This is the same one-time install that
# README describes for local dev.
COPY libs/qudo-jni-crypto-1.0.0.jar /tmp/qudo-jni.jar
COPY libs/qudo-jni-crypto-1.0.0.pom /tmp/qudo-jni.pom
RUN mvn install:install-file -Dfile=/tmp/qudo-jni.jar -DpomFile=/tmp/qudo-jni.pom \
    -DgroupId=com.qudo -DartifactId=qudo-jni-crypto -Dversion=1.0.0 -Dpackaging=jar -q

COPY pom.xml .
RUN mvn dependency:go-offline -B 2>/dev/null || true
COPY src ./src
RUN mvn package -DskipTests -B

FROM qudo-pqc-runtime:latest
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar
EXPOSE 8093
ENTRYPOINT ["java", "-Djava.library.path=/app/lib", "-jar", "app.jar"]
