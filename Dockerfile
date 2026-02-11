# Étape 1 : Compilation
FROM maven:3.9-eclipse-temurin-21-alpine AS builder
COPY src /home/app/src
COPY pom.xml /home/app
RUN mvn -f /home/app/pom.xml clean package -DskipTests

# Étape 2 : Image finale (légère)
FROM eclipse-temurin:21-jre-alpine
COPY --from=builder /home/app/target/*.jar app.jar
ENTRYPOINT ["java","-jar","/app.jar"]
EXPOSE 8081
