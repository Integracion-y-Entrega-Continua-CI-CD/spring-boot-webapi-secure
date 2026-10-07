# ---- Build stage ----
FROM maven:3.9-eclipse-temurin-25-alpine AS builder
WORKDIR /app

# Copy pom first (better layer caching)
COPY pom.xml .

# Download dependencies (cached unless pom changes)
RUN mvn -B dependency:go-offline

# Copy source and build
COPY src src
RUN mvn -B package -DskipTests

# ---- Runtime stage ----
FROM eclipse-temurin:25-jre-alpine

# Security: run as non-root user (Alpine usa addgroup/adduser)
RUN addgroup -S spring && adduser -S spring -G spring
USER spring:spring

WORKDIR /app

# Copy only the fat jar
COPY --from=builder /app/target/*.jar app.jar

# Optional: expose actuator / app port
EXPOSE 8080

# Health check (Alpine trae wget, no curl)
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD wget -qO- http://localhost:8080/actuator/health || exit 1

ENTRYPOINT ["java", "-XX:+UseContainerSupport", "-XX:MaxRAMPercentage=75.0", "-jar", "app.jar"]
