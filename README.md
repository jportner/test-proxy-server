Test Proxy Server
=================

A single user SVMP proxy server intended for connecting one instance of
the client to one backend SVMP virtual machine for testing purposes.

Building
========

Prerequisites:
*  JDK 6 or newer (with 'java' and 'keytool' in your PATH, or at least make sure `JAVA_HOME` is set)
*  ant

Build Steps:
1. Check out the SVMP client and protocol to a directory of your choice
        cd ${SVMP}
        git clone https://github.com/SVMP/svmp-protocol-def.git -b svmp-1.1
        git clone https://github.com/SVMP/test-proxy-server.git -b svmp-1.1
2.  Update the VM_ADDRESS, USE_SSL, STUN server and other static variables in 
    TestProxy.java to suit your testing environment.
3.  Build and run the test proxy:
        cd ${SVMP}/test-proxy-server
        ./test-proxy.sh

License
=======
Copyright (c) 2012-2013, The MITRE Corporation, All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
