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

import java.text.SimpleDateFormat;
import java.util.*;
import java.util.Map.Entry;

/**
 * @author Joe Portner
 * Manages all SessionInfo objects, also spawns a Timer to handle cleaning up expired sessions
 */
public class SessionHandler {
    private static final long TIMER_CLEANUP_INTERVAL = 60*60*1000; // cleanup interval in ms (default: 60 minutes)

    private static SessionHandler instance;

    private TreeMap<String, SessionInfo> sessions = new TreeMap<String, SessionInfo>();
    private Timer cleanupTimer = new Timer();
    private final Object sessionLock = new Object();

    // no public instantiations
    private SessionHandler() {
        // this cleanup timer runs at a certain interval and removes sessions that are expired
        cleanupTimer.scheduleAtFixedRate(new SessionCleanupTask(), TIMER_CLEANUP_INTERVAL, TIMER_CLEANUP_INTERVAL);
    }

    // creates an instance of a SessionHandler
    public static void init() {
        if (instance == null)
            instance = new SessionHandler();
    }

    // overload for creating a brand new session without reusing an old one
    public static String newSession(TestProxy testProxy, String username) {
        return newSession(testProxy, username, null);
    }
    // creates a new session, and removes old session if it exists
    public static String newSession(TestProxy testProxy, String username, String oldToken) {
        //init();
        return instance._newSession(testProxy, username, oldToken);
    }

    private String _newSession(TestProxy testProxy, String username, String oldToken) {
        synchronized (sessionLock) {
            // if there is an old session, remove it from the map
            SessionInfo oldSession = null;
            if (oldToken != null && instance.sessions.containsKey(oldToken))
                oldSession = instance.sessions.remove(oldToken);

            // either create a brand new session, or recreate an old one (reuses "firstCreated")
            SessionInfo newSession;
            if (oldSession == null)
                newSession = new SessionInfo(testProxy, username);
            else
                newSession = new SessionInfo(testProxy, oldSession);

            // put the new session in the map and return it
            instance.sessions.put(newSession.getSessionToken(), newSession);
            return newSession.getSessionToken();
        }
    }

    // check if a given session token is valid (i.e. has been created, username matches, and has not expired yet)
    public static boolean isValid(String username, String token) {
        //init();
        return instance._isValid(username, token);
    }

    private boolean _isValid(String username, String token) {
        synchronized (sessionLock) {
            return token != null
                    && instance.sessions.containsKey(token)
                    && instance.sessions.get(token).isValid(username);
        }
    }

    // this task runs periodically and cleans up expired sessions (those that have disconnected before expiration)
    class SessionCleanupTask extends TimerTask {
        public void run() {
            synchronized (sessionLock) {
                System.out.printf("[%s] ***RUNNING SESSION CLEANUP***%n",
                        new SimpleDateFormat("HH:mm:ss").format(new Date()));
                // generate sorted set of sessions based on expiration (ascending)
                SortedSet<Entry<String, SessionInfo>> sortedEntries = new TreeSet<Entry<String, SessionInfo>>(
                        new Comparator<Entry<String, SessionInfo>>() {
                            @Override public int compare(Entry<String, SessionInfo> e1, Entry<String, SessionInfo> e2) {
                                return e1.getValue().compareTo(e2.getValue());
                            }
                        }
                );
                sortedEntries.addAll(sessions.entrySet());

                // loop through sorted set of sessions
                boolean removed = false;
                for (Entry<String, SessionInfo> entry : sortedEntries) {
                    // if this session is expired, remove it from the session map
                    if (entry.getValue().isExpired()) {
                        removed = true;
                        System.out.println("   Removing session: " + entry.getKey());
                        sessions.remove(entry.getKey());
                    }
                    // otherwise, the rest of the sessions in this sorted set aren't expired; break out of the loop
                    else
                        break;
                }
                if (!removed)
                    System.out.println("   No sessions are expired.");
            }
        }
    }
}
