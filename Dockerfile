# ── Stage 1: Build ───────────────────────────────────────────────────────────
# Cache Maven dependencies in a separate layer so rebuilds after source-only
# changes don't re-download the internet.
FROM maven:3.9.6-eclipse-temurin-21-alpine AS build
WORKDIR /app

COPY pom.xml .
RUN mvn dependency:go-offline -q

COPY src ./src
RUN mvn package -DskipTests -q

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
# JRE-only image — no compiler, no Maven, no source. ~100 MB vs ~600 MB for JDK.
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# Non-root user — never run production JVMs as root
RUN addgroup -S spring && adduser -S spring -G spring
USER spring

COPY --from=build /app/target/*.jar app.jar

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
