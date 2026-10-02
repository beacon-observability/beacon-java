FROM busybox:1.36.1

ARG AGENT_JAR=beacon-javaagent-1.0.0.jar
COPY ${AGENT_JAR} /javaagent.jar

USER 65532:65532
