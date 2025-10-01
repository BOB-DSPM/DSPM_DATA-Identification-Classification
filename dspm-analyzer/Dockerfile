FROM gradle:8.5-jdk17 AS builder

WORKDIR /app

COPY build.gradle settings.gradle gradlew ./
COPY gradle/ gradle/

RUN gradle dependencies --no-daemon

COPY src/ src/

RUN gradle build --no-daemon -x test

FROM eclipse-temurin:17-jre-alpine

WORKDIR /app

# Install curl for health check
RUN apk add --no-cache curl

# Create non-root user for security (Alpine Linux)
RUN addgroup -S dspm && adduser -S dspm -G dspm

COPY --from=builder /app/build/libs/*.jar app.jar

RUN chown dspm:dspm app.jar

USER dspm

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/actuator/health || exit 1

ENTRYPOINT ["java", "-jar", "/app/app.jar"]
