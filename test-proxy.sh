#!/bin/sh

# Key store password, must match that in TestProxy.jar
KEYSTORE_PASS="changeme"

KEYTOOL=$JAVA_HOME/bin/keytool
JAVA=$JAVA_HOME/bin/java

if [ ! -f test.keystore.jks ]
then
    $KEYTOOL -genkey -keyalg RSA -alias svmp-test-proxy -keystore test.keystore.jks \
        -storepass $KEYSTORE_PASS -keypass $KEYSTORE_PASS -validity 360 -keysize 2048 \
        -dname "CN=svmp.test"
fi

ant
$JAVA -classpath ./dist/svmp-test-proxy.jar org.mitre.svmp.TestProxy.TestProxy
