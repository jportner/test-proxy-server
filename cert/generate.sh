#!/bin/bash
# Author: Joe Portner
# Running this script will delete any existing keys/certificates and create new ones
# Adapted from guide: http://blog.callistaenterprise.se/2011/11/24/creating-self-signed-certificates-for-use-on-android/
# Requires JCE unlimited policy files 6: http://www.oracle.com/technetwork/java/javasebusiness/downloads/java-archive-downloads-java-plat-419418.html#jce_policy-6-oth-JPR
# (JCE .jar files go in "jre/lib/security")

# Change these variables
CLIENT_PKEY_PASS="changeme_clientkeypass"
SERVER_PKEY_PASS="changeme_serverkeypass"
SERVER_STORE_PASS="changeme_serverstorepass" # used for trust store and key store
CLIENT_PKEY_BITS=2048
SERVER_PKEY_BITS=2048

# No need to change these variables
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )" # the directory this script is in
OUT_PATH="$DIR/out"
CLIENT_CERT_CONFIG="$DIR/config/client_cert.config"
SERVER_CERT_CONFIG="$DIR/config/server_cert.config"
C_PKEY="$OUT_PATH/client_pkey.pem"
S_PKEY="$OUT_PATH/server_pkey.pem"
C_CERT="$OUT_PATH/client_cert.pem"
S_CERT="$OUT_PATH/server_cert.pem"
S_TSTORE="$OUT_PATH/server_tstore.jks"
C_KANDC="$OUT_PATH/client_pkey_and_cert.p12"
S_KANDC="$OUT_PATH/server_pkey_and_cert.p12"
S_KSTORE="$OUT_PATH/server_kstore.jks"

# Verify the user has keytool
KEYTOOL=`which keytool`
if [[ -z $JAVA || -z $KEYTOOL ]] ; then
  echo "Can't find keytool on the path. Trying JAVA_HOME."
  if [ -z $JAVA_HOME ] ; then
    echo JAVA_HOME not set. Aborting.
    exit 1
  else
    KEYTOOL=$JAVA_HOME/bin/keytool
  fi  
fi

echo "Generating mutual SSL certificates..."
echo ""

# Make the output directory if it doesn't exist
mkdir -p "$OUT_PATH"

####################################################################
echo "1. CREATE PRIVATE KEYS"
rm -f "$C_PKEY"
rm -f "$S_PKEY"
openssl genrsa -des3 -passout "pass:$CLIENT_PKEY_PASS" -out "$C_PKEY" $CLIENT_PKEY_BITS
openssl genrsa -des3 -passout "pass:$SERVER_PKEY_PASS" -out "$S_PKEY" $SERVER_PKEY_BITS
echo ""

####################################################################
echo "2. CREATE SELF-SIGNED CERTIFICATES"
rm -f "$C_CERT"
rm -f "$S_CERT"
openssl req -new -x509 -key "$C_PKEY" -passin "pass:$CLIENT_PKEY_PASS" -out "$C_CERT" -days 365 -config "$CLIENT_CERT_CONFIG"
openssl req -new -x509 -key "$S_PKEY" -passin "pass:$SERVER_PKEY_PASS" -out "$S_CERT" -days 365 -config "$SERVER_CERT_CONFIG"
echo ""

####################################################################
echo "3. CREATE TRUST STORE"
rm -f "$S_TSTORE"
# Create a trust store for the server and import the client’s certificate into it.
$KEYTOOL -importcert -trustcacerts -keystore "$S_TSTORE" -storetype jks -storepass "$SERVER_STORE_PASS" -file "$C_CERT" -noprompt
echo ""

####################################################################
echo "4. COMBINE KEYS AND CERTIFICATES"
rm -f "$C_KANDC"
rm -f "$S_KANDC"
# Combine the certificate and the private key for the server and client respectively:
openssl pkcs12 -export -inkey "$C_PKEY" -passin "pass:$CLIENT_PKEY_PASS" -in "$C_CERT" -passout "pass:$CLIENT_PKEY_PASS" -out "$C_KANDC"
openssl pkcs12 -export -inkey "$S_PKEY" -passin "pass:$SERVER_PKEY_PASS" -in "$S_CERT" -passout "pass:$SERVER_PKEY_PASS" -out "$S_KANDC"
echo ""

####################################################################
echo "5. CONVERT FROM PKCS12"
rm -f "$S_KSTORE"
# Import the created keystore to new one with common format:
# (note: deststorepass and destkeypass have to be the same)
$KEYTOOL -importkeystore -srckeystore "$S_KANDC" -srcstoretype PKCS12 -srcstorepass "$SERVER_PKEY_PASS" -destkeystore "$S_KSTORE" -deststoretype jks -deststorepass "$SERVER_STORE_PASS"
echo ""

####################################################################
echo "6. CLEANUP"
rm -f "$C_PKEY"
rm -f "$S_PKEY"
rm -f "$C_CERT"
rm -f "$S_CERT"
rm -f "$S_KANDC"
echo ""

echo "Done!"
echo ""
# We should now have all files we need for a successful TLS/SSL mutual authentication.
# The files we use in our test proxy will be: server_kstore.jks and server_tstore.jks.
# The file we install on our Android device for certificate authentication (optional, ICS+ only): client_pkey_and_cert.p12
