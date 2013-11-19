#!/bin/sh

# Key store password, must match that in TestProxy.jar
KEYSTORE_PASS="changeme"

JAVA=`which java`
KEYTOOL=`which keytool`
if [[ -z $JAVA || -z $KEYTOOL ]] ; then
  echo "Can't find java or keytool on the path. Trying JAVA_HOME."
  if [ -z $JAVA_HOME ] ; then
    echo JAVA_HOME not set. Aborting.
    exit 1
  else
    KEYTOOL=$JAVA_HOME/bin/keytool
    JAVA=$JAVA_HOME/bin/java
  fi  
fi



if [ ! -f test.keystore.jks ]
then
    $KEYTOOL -genkey -keyalg RSA -alias svmp-test-proxy -keystore test.keystore.jks \
        -storepass $KEYSTORE_PASS -keypass $KEYSTORE_PASS -validity 360 -keysize 2048 \
        -dname "CN=svmp.test"
fi

ant
$JAVA -classpath ./dist/svmp-test-proxy.jar:../svmp-protocol-def/protobuf-2.5.0/protobuf-java-2.5.0.jar org.mitre.svmp.TestProxy.TestProxy
