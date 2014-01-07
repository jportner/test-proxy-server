#!/bin/bash

# Verify the user has Java installed, and find it
export JAVA=`which java`
if [[ -z $JAVA ]] ; then
  echo "Can't find java on the path. Trying JAVA_HOME."
  if [ -z $JAVA_HOME ] ; then
    echo JAVA_HOME not set. Aborting.
    exit 1
  else
    JAVA=$JAVA_HOME/bin/java
  fi  
fi

# Verify a server certificate exists; if not, generate one
if [ ! -f "./cert/out/server_kstore.jks" ]
then
    echo "Server certificate not found."
    source "./cert/generate.sh"
fi

ant
$JAVA -classpath ./dist/svmp-test-proxy.jar:svmp-protocol-def/protobuf-2.5.0/protobuf-java-2.5.0.jar org.mitre.svmp.TestProxy.TestProxy
