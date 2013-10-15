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

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Timer;
import java.util.TimerTask;

/**
 * @author Joe Portner
 * Stores information about a session, also spawns a Timer to handle refreshing its expiration date
 */
public class SessionInfo implements Comparable<SessionInfo> {
    private static final long SESSION_MAX_TIMEOUT = 4*60*60*1000; // max session lifespan in ms (default: 4 hrs)
    private static final long SESSION_IDLE_TIMEOUT = 15*60*1000; // idle session lifespan in ms (default: 15 min)
    private static final long SESSION_REUSE_LIMIT = 15*60*1000; // session reuse limit in ms (default: 15 min)
    private static final long TIMER_UPDATE_INTERVAL = 60*1000; // update interval in ms (default: 60 seconds)

    // used to generate random session token strings
    private static SecureRandom secureRandom = new SecureRandom();

    private TestProxy testProxy;
    private String username;
    private String sessionToken;
    private Date firstCreated;
    private Date lastUpdated;
    private Timer timer;

    // if we're creating a brand new SessionInfo, start with a fresh "firstCreated" Date
    public SessionInfo(TestProxy testProxy, String username) {
        this(testProxy, username, new Date());
    }

    // if we're recreating an old SessionInfo, reuse the "firstCreated" Date
    public SessionInfo(TestProxy testProxy, SessionInfo oldSession) {
        this(testProxy, oldSession.username, oldSession.firstCreated);
    }

    // this is used for creating a brand new SessionInfo OR recreating an old one
    public SessionInfo(TestProxy testProxy, String username, Date firstCreated) {
        this.testProxy = testProxy;
        this.username = username;
        this.sessionToken = new BigInteger(130, secureRandom).toString(32); // create a random session token
        this.firstCreated = firstCreated;
        this.lastUpdated = testProxy.getLastUpdated();
        // schedule a timer to periodically check if the session has reached a max life timeout or idle timeout
        timer = new Timer();
        timer.scheduleAtFixedRate(new SessionUpdateTask(), TIMER_UPDATE_INTERVAL, TIMER_UPDATE_INTERVAL);
    }

    public String getSessionToken() {
        return sessionToken;
    }

    // for a session to be valid, the username must match the stored value AND the session must not be expired
    public boolean isValid(String username) {
        return this.username.equals(username) && !isExpired();
    }

    // a session is expired if either the last update is older than the session reuse limit,
    // or the first creation date/time is older than the max session lifespan
    public boolean isExpired() {
        return lastUpdated.before(new Date(System.currentTimeMillis() - SESSION_REUSE_LIMIT))
                || firstCreated.before(new Date(System.currentTimeMillis() - SESSION_MAX_TIMEOUT));
    }

    // checks to make sure the max timeout and idle timeout have not been reached
    public boolean checkTimeouts() {
        System.out.printf("[%s] Checking session [sessionToken '%s'] timeouts: ",
                new SimpleDateFormat("HH:mm:ss").format(new Date()), getSessionToken());

        if (firstCreated.before(new Date(System.currentTimeMillis() - SESSION_MAX_TIMEOUT))) {
            try {
                System.out.println("max timeout reached, terminating connection...");
                SessionHandler.removeSession(sessionToken); // remove the session from the treemap

                // send a message to the client notifying them to re-authenticate, and terminate the connection
                testProxy.sessionMaxTimeout();
            } catch (IOException e) {
                System.out.println("   Error: " + e.getMessage());
            }
            return false;
        }
        else if (lastUpdated.before(new Date(System.currentTimeMillis() - SESSION_IDLE_TIMEOUT))) {
            try {
                System.out.println("idle timeout reached, terminating connection...");
                SessionHandler.removeSession(sessionToken); // remove the session from the treemap

                // send a message to the client notifying them to re-authenticate, and terminate the connection
                testProxy.sessionIdleTimeout();
            } catch (IOException e) {
                System.out.println("   Error: " + e.getMessage());
            }
            return false;
        }

        System.out.println("session is still valid");
        return true;
    }

    // the client closed the connection, refresh the "lastUpdated" time and cancel the update timer
    public void closeSession() {
        refreshLastUpdated();
        timer.cancel();
    }

    // sets the "lastUpdated" time to the current time, up to the largest time that will not surpass the max timeout
    private void refreshLastUpdated() {
        this.lastUpdated = testProxy.getLastUpdated();
        System.out.printf("[%s] Refreshing session update time: [sessionToken '%s', lastUpdated '%s']%n",
                new SimpleDateFormat("HH:mm:ss").format(new Date()),
                getSessionToken(),
                new SimpleDateFormat("HH:mm:ss").format(lastUpdated));
    }

    // used by SessionHandler cleanup timer, sorts in ascending chronological order
    public int compareTo(SessionInfo otherSession) {
        return firstCreated.compareTo(otherSession.firstCreated);
    }

    // this task runs periodically and either extends the expiration time or terminates the connection of the session
    class SessionUpdateTask extends TimerTask {
        public void run() {
            refreshLastUpdated();
            // if the test proxy is closed, cancel this TimerTask and future ones (should be done automatically anyways)
            // if checkTimeouts() failed, we reached the max timeout value; terminate the connection
            if (testProxy.isClosed() || !checkTimeouts())
                timer.cancel();
        }
    }
}
