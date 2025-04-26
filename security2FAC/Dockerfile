FROM amazoncorretto:17
WORKDIR /opt
CMD ["./gradlew", "clean", "bootJar"]
ARG JAR_FILE=build/libs/*.jar
COPY ${JAR_FILE} security2FAC-0.0.1-SNAPSHOT.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "security2FAC-0.0.1-SNAPSHOT.jar"]
