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
    private static final long SESSION_REUSE_TIMEOUT = 15*60*1000; // max token reuse lifespan in ms (default: 15 min)
    private static final long TIMER_UPDATE_INTERVAL = 60*1000; // update interval in ms (default: 60 seconds)

    // used to generate random session token strings
    private static SecureRandom secureRandom = new SecureRandom();

    private TestProxy testProxy;
    private String username;
    private String sessionToken;
    private Date firstCreated;
    private Date lastUpdated;

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
        refreshLastUpdated();
        // schedule a timer to periodically update the session's 'firstCreated' value, extends session reuse expiration
        Timer timer = new Timer();
        timer.scheduleAtFixedRate(new SessionUpdateTask(timer), TIMER_UPDATE_INTERVAL, TIMER_UPDATE_INTERVAL);
    }

    public String getSessionToken() {
        return sessionToken;
    }

    // for a session to be valid, the username must match the stored value AND the session must not be expired
    public boolean isValid(String username) {
        return this.username.equals(username) && !isExpired();
    }

    public boolean isExpired() {
        return !lastUpdated.after(new Date(System.currentTimeMillis() - SESSION_REUSE_TIMEOUT));
    }

    // if the maximum session length has not been exceeded, extend the session timeout
    public boolean update() {
        System.out.printf("[%s] Updating session '%s' expiration: ",
                new SimpleDateFormat("HH:mm:ss").format(new Date()), getSessionToken());
        if (firstCreated.after(new Date(System.currentTimeMillis() - SESSION_MAX_TIMEOUT))) {
            refreshLastUpdated();
            System.out.println("success");
            return true;
        }

        try {
            System.out.println("max timeout reached, terminating connection...");
            lastUpdated = new Date(System.currentTimeMillis() - SESSION_REUSE_TIMEOUT); // expire the session

            // send a message to the client notifying them to re-authenticate, and terminate the connection
            testProxy.sessionMaxTimeout();
        } catch (IOException e) {
            System.out.println("   Error: " + e.getMessage());
        }
        return false;
    }

    // sets the "lastUpdated" time to the current time, up to the largest time that will not surpass the max timeout
    private void refreshLastUpdated() {
        // the largest "lastUpdated" time that will not surpass the max timeout
        long maxLastUpdated = firstCreated.getTime() + SESSION_MAX_TIMEOUT - SESSION_REUSE_TIMEOUT;

        // if the current time is larger than the largest "lastUpdated" time we will accept...
        if (System.currentTimeMillis() > maxLastUpdated)
            this.lastUpdated = new Date(maxLastUpdated);
            // TODO: some sort of warning to the client that the connection will be terminated soon?
        else
            this.lastUpdated = new Date();
    }

    // used by SessionHandler cleanup timer, sorts in ascending chronological order
    public int compareTo(SessionInfo otherSession) {
        return firstCreated.compareTo(otherSession.firstCreated);
    }

    // this task runs periodically and either extends the expiration time or terminates the connection of the session
    class SessionUpdateTask extends TimerTask {
        private Timer timer;
        public SessionUpdateTask(Timer timer) {
            this.timer = timer;
        }
        public void run() {
            // if the test proxy is closed, cancel this TimerTask and future ones (should be done automatically anyways)
            // if update() failed, we reached the max timeout value; terminate the connection
            if (testProxy.isClosed() || !update())
                timer.cancel();
        }
    }
}
