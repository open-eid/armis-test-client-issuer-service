# Issuer service for test client applet

This is an Issuer REST API implementation that performs personalization of test client applet (an example third party applet).

Refer to [issuer-openapi.yml](issuer-openapi.yml) for description of Issuer REST API.

## Prerequisites

* Java 17 JDK

## Building and running the application

```bash
./mvnw clean spring-boot:run
```

## Building executable JAR

```bash
./mvnw clean package
```
The resulting JAR file, which includes all the required dependencies, is located at `target/test-client-issuer-service-*-exec.jar`. 
It can be executed by running:
```bash
java -jar test-client-issuer-service-*-exec.jar
```
