#!/bin/sh

CLASSPATH=bin
CLASSPATH=$CLASSPATH:lib/acme4j-client-2.10.jar
CLASSPATH=$CLASSPATH:lib/guava-21.0.jar
CLASSPATH=$CLASSPATH:lib/slf4j-api-1.7.9.jar
CLASSPATH=$CLASSPATH:lib/slf4j-jdk14-1.7.9.jar
CLASSPATH=$CLASSPATH:lib/jose4j-0.7.2.jar
CLASSPATH=$CLASSPATH:lib/protobuf-2.6.1.jar

java \
  -cp $CLASSPATH \
  letsencrypt.Main $@
