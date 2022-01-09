FROM adoptopenjdk:11-jre-hotspot
ADD target/diplom-0.0.1-SNAPSHOT.jar app.jar
ENTRYPOINT ["java", "-jar", "app.jar"]