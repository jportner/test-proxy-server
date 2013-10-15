/*
 * Copyright 2013 The MITRE Corporation, All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this work except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package org.mitre.svmp.TestProxy;

import org.mitre.svmp.protocol.SVMPProtocol.AuthenticationEntry;
import org.mitre.svmp.protocol.SVMPProtocol.Request;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

/**
 * @author Joe Portner
 * Manages authentication, utilizes the SessionHandler
 */
public class AuthenticationHandler {
    public static String authenticate(TestProxy testProxy, Request request) {
        String newToken = null;

        if (request.hasAuthentication()) {
            try {
                String username = request.getAuthentication().getUsername();
                System.out.printf("[%s] Got auth data: [username '%s'",
                        new SimpleDateFormat("HH:mm:ss").format(new Date()),
                        username);

                // try to authenticate from a session token!
                if (request.getAuthentication().hasSessionToken()) {
                    String oldToken = request.getAuthentication().getSessionToken();
                    System.out.printf(", sessionToken '%s']%n", oldToken);

                    // check to make sure that the token is valid (i.e. it is known, and it is not expired)
                    if (SessionHandler.isValid(username, oldToken)) {
                        newToken = SessionHandler.newSession(testProxy, username, oldToken);
                        System.out.printf("   Session token authenticated successfully, new token: '%s'%n", newToken);
                    }
                    else
                        System.out.println("   Session token is not valid and has been rejected");
                }
                // we don't have a session token, try to authenticate from the provided AuthenticationEntry collection
                else {
                    HashMap<String, byte[]> authEntries = new HashMap<String, byte[]>();
                    StringBuilder stringBuilder = new StringBuilder();

                    // loop through AuthenticationEntry collection, store keys and values in the authEntries HashMap
                    List<AuthenticationEntry> entryList = request.getAuthentication().getEntriesList();
                    for (AuthenticationEntry entry : entryList) {
                        String key = entry.getKey();
                        byte[] value = entry.getValue().toByteArray();

                        // put authentication key and value into map of entries
                        authEntries.put(entry.getKey(), entry.getValue().toByteArray());

                        // debug output
                        String valueString = new String(value).length() > 0 ? "..." : "";
                        stringBuilder.append(String.format(", %s '%s'", key, valueString));
                    }
                    stringBuilder.append("]");
                    System.out.println(stringBuilder.toString());

                    // we don't currently authenticate passwords/etc, so if we didn't have a session, make a new one
                    newToken = SessionHandler.newSession(testProxy, username);

                    if (newToken != null)
                        System.out.printf("   Authentication successful, new token: '%s'%n", newToken);
                    else
                        System.out.println("   Authentication is not valid and has been rejected");
                }
            } catch (Exception e) {
                System.out.println("Error parsing authentication: " + e.getMessage());
            }
        }

        return newToken;
    }
}
