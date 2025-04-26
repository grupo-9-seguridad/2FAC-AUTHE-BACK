FROM gradle:8.5-jdk17 AS build
WORKDIR /app
COPY --chown=gradle:gradle . .
RUN gradle clean bootJar

FROM amazoncorretto:17
WORKDIR /opt
COPY --from=build /app/build/libs/*.jar security2FAC.jar
EXPOSE 8080 587
ENTRYPOINT ["java", "-jar", "security2FAC.jar"]
