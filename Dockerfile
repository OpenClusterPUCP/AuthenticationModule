FROM openjdk:17
VOLUME /tmp
COPY "target/AuthenticationModule-0.0.1-SNAPSHOT.jar" /tmp
ENTRYPOINT