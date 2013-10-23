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

/**
 * Single client test proxy for the SVMP protocol
 */
package org.mitre.svmp.TestProxy;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Date;

import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import com.google.protobuf.InvalidProtocolBufferException;

import org.mitre.svmp.protocol.SVMPProtocol;
import org.mitre.svmp.protocol.SVMPProtocol.AuthResponse;
import org.mitre.svmp.protocol.SVMPProtocol.AuthResponse.AuthResponseType;
import org.mitre.svmp.protocol.SVMPProtocol.Request;
import org.mitre.svmp.protocol.SVMPProtocol.Request.RequestType;
import org.mitre.svmp.protocol.SVMPProtocol.Response;
import org.mitre.svmp.protocol.SVMPProtocol.VideoStreamInfo;
import org.mitre.svmp.protocol.SVMPProtocol.WebRTCMessage;
import org.mitre.svmp.protocol.SVMPProtocol.Response.ResponseType;
import org.mitre.svmp.protocol.SVMPProtocol.WebRTCMessage.WebRTCType;

/**
 * @author David Keppler <dkeppler@mitre.org>
 *
 */
public class TestProxy {

	// Set this to the IP address of the SVMP VM.
	public static final String VM_ADDRESS = "192.168.42.100";
    // public static String VM_ADDRESS = "127.0.0.1";

	// STUN server Host:Port to use
	// set to null to use the proxy server's IP and default port 3478
	public static String STUN_SERVER = null;
	// public static String STUN_SERVER = "192.168.42.120:3478";

	// To use SSL:
	// 1) use keytool to generate a self signed cert in a new keystore
	// 2) set the keystore file name and password here and set USE_SSL to true
	private static final boolean USE_SSL = false;
	private static final String KEYSTORE_FILE = "test.keystore.jks";
	private static final String KEYSTORE_PASS = "changeme";

	public static int INPUT_SERVICE_PORT = 8001;

	public static final int LISTEN_PORT = 8002;

	private static final boolean DEBUG = true;

	// private static final int UNAUTHENTICATED = 0;
	// private static final int AUTHENTICATED = 1;
	// private static final int PROXYING = 2;
	// private static final int VIDEOINFO = 3;
	private enum State {
	    UNAUTHENTICATED, AUTHENTICATED, VIDEOINFO, PROXYING,
	}

	private Socket inputService = null;
	private InputStream  inputServiceIn = null;
	private OutputStream inputServiceOut = null;
	private Thread inputServiceThread;

    private boolean sessionTimedOut;
    private AuthResponseType sessionTimedOutType;
    private Date lastUpdated;

	private State state = State.UNAUTHENTICATED;

	Socket session;
	
	public TestProxy(Socket s) {
		session = s;
	}
	
	/**
	 * @param args
	 * @throws IOException
	 * @throws InterruptedException 
	 */
	public static void main(String[] args) throws Exception {
		ServerSocket daemon = getServerSocket().createServerSocket(LISTEN_PORT);
		System.out.println("Listen socket opened on port " + LISTEN_PORT);

        // we have to start the session handler here to ensure the cleanup timer task will run reliably
        SessionHandler.init();

		while (true) {
			TestProxy session = null;
			try {
				Socket s = daemon.accept();
				System.out.println("Client connection received from " + s.getInetAddress());

				// use local IP of the socket if no STUN server set
				if (STUN_SERVER == null) {
					STUN_SERVER = "" + s.getLocalAddress().getHostAddress()
							+ ":3478";
				}

				session = new TestProxy(s);
				session.run();
			} catch (Exception e) {
				e.printStackTrace();
				if (session != null)
					session.cleanup();
			}
		}
	}

    public boolean isClosed() {
        return session == null || session.isClosed();
    }

    // called from SessionInfo when the session has reached its maximum lifespan, triggers a connection termination
    public void sessionMaxTimeout() throws IOException {
        sessionTimedOutType = AuthResponseType.SESSION_MAX_TIMEOUT;
        sessionTimeout();
    }

    // called from SessionInfo when the session has reached its maximum lifespan, triggers a connection termination
    public void sessionIdleTimeout() throws IOException {
        sessionTimedOutType = AuthResponseType.SESSION_IDLE_TIMEOUT;
        sessionTimeout();
    }

    private void sessionTimeout() throws IOException {
        sessionTimedOut = true;

        System.out.println("   Sending re-authenticate message to client...");
        // send a message to the client notiying them to re-authenticate
        AuthResponse.Builder arBuilder = AuthResponse.newBuilder();
        arBuilder.setType(sessionTimedOutType);

        Response.Builder response = Response.newBuilder();
        response.setType(ResponseType.AUTH);
        response.setAuthResponse(arBuilder);
        synchronized(outLock) {
            response.build().writeDelimitedTo(session.getOutputStream());
        }

        // terminate the proxy connection
        cleanup();
    }

    // the last touch input we have received (used to time out idle sessions)
    public Date getLastUpdated() {
        return lastUpdated;
    }

	private static ServerSocketFactory getServerSocket() throws Exception {
		if (USE_SSL) {
			FileInputStream keyFile = new FileInputStream(KEYSTORE_FILE);
			char[] keyPass = KEYSTORE_PASS.toCharArray();
			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
			ks.load(keyFile, keyPass);

			KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			kmf.init(ks, keyPass);

			// server authentication only, no client auth here so no TrustManager needed
			SSLContext sslcontext = SSLContext.getInstance("TLS");
			sslcontext.init(kmf.getKeyManagers(), null, new SecureRandom());

			return sslcontext.getServerSocketFactory();
		} else {
			return ServerSocketFactory.getDefault();
		}
	}

    private final Object outLock = new Object();
	private void run() throws IOException, InterruptedException {
		InputStream in = session.getInputStream();
		OutputStream out = session.getOutputStream();
        lastUpdated = new Date();
        String sessionToken = null;

		System.out.println("Starting listen loop");

		while (!session.isClosed() && !sessionTimedOut) {

			// try to parse the Request that is sent from the client
			Request req = null;
			try {
				req = Request.parseDelimitedFrom(in);
			} catch( InvalidProtocolBufferException e ) {
				if( e.getMessage().equals("Protocol message contained an invalid tag (zero).") )
					System.out.println("ERROR: Client tried to connect using SSL, proxy's SSL is turned off");
				else if( e.getMessage().equals("Remote host closed connection during handshake") )
					System.out.println("ERROR: Client tried to connect using SSL, proxy's SSL certificate was rejected");
				else if( e.getMessage().equals("Unrecognized SSL message, plaintext connection?") )
					System.out.println("ERROR: Client tried to connect without using SSL, proxy's SSL is turned on");
                else if (e.getMessage().equals("sun.security.validator.ValidatorException: PKIX path validation failed:"
                        + " java.security.cert.CertPathValidatorException: signature check failed"))
                    System.out.println("ERROR: Client certificate authentication failed");
				else
					System.out.println("ERROR: failed parsing Request from client: " + e.getMessage());
			}

			if( req == null ) {
                // if the request is null because we are terminating the connection, break out of this loop
                if (sessionTimedOut)
                    break;

                // the user terminated the connection manually, renew lastUpdated time to extend session reuse limit
                lastUpdated = new Date();
                SessionHandler.closeSession(sessionToken);

				System.out.println("Client disconnected, ending thread");
				// sendWebRTCBye();
				cleanup();
				return;
			}

			// do debug printing of the received message
			debugUpstream(req);

			Response.Builder response = SVMPProtocol.Response.newBuilder();
			switch (state) {
			case UNAUTHENTICATED:
                response.setType(ResponseType.AUTH);
                AuthResponse.Builder arBuilder = AuthResponse.newBuilder();

                // try to get a new session token based on the Request; failure results in a null value
                sessionToken = AuthenticationHandler.authenticate(this, req);

                // if we got a session token, then we authenticated successfully!
				if (sessionToken != null) {
                    arBuilder.setType(AuthResponseType.AUTH_OK); // set the AuthResponse type
                    arBuilder.setSessionToken(sessionToken); // add the session token to the AuthResponse protobuf
                    response.setAuthResponse(arBuilder); // wrap the AuthResponse in the Response protobuf

					synchronized(outLock) {
						response.build().writeDelimitedTo(out);
						System.out.println("AUTH_OK sent");
					}

					// connect to VM, send it the video params, and wait for VMREADY
					connectToVM(out);

					response.clear();
					response.setType(ResponseType.VMREADY);
					response.setMessage(VM_ADDRESS);
                    state = State.VIDEOINFO;
					synchronized(outLock) {
						response.build().writeDelimitedTo(out);
						System.out.println("VMREADY sent");
					}
				} else {
                    arBuilder.setType(AuthResponseType.AUTH_FAIL); // set the AuthResponse type
                    response.setAuthResponse(arBuilder); // wrap the AuthResponse in the Response protobuf

					synchronized(outLock) {
						response.build().writeDelimitedTo(out);
						System.out.println("AUTH_FAIL sent");
					}
					// failed or unexpected message type
				}
				break;
			case AUTHENTICATED:
				break;
			case VIDEOINFO:
				if (req.getType() == RequestType.VIDEO_PARAMS) {
					Response.newBuilder().setType(ResponseType.VIDSTREAMINFO)
							.setVideoInfo(makeVideoChannelInfo()).build()
							.writeDelimitedTo(out);
					state = State.PROXYING;
			    } else {
			        // unexpected message type, ignore
			    }
			    break;
			case PROXYING:
                switch(req.getType()) {
                    case TOUCHEVENT:
                        // screen was touched, renew lastUpdated time to extend session idle timeout and reuse limit
                        lastUpdated = new Date();
                        break;
				default:
					break;
                }

				req.writeDelimitedTo(inputServiceOut);
				break;	// PROXYING state
			}
		}
	}

	private void sendWebRTCBye() throws IOException {
		Request.newBuilder()
				.setType(RequestType.WEBRTC)
				.setWebrtcMsg(
						WebRTCMessage.newBuilder().setType(WebRTCType.BYE))
				.build().writeDelimitedTo(inputServiceOut);
	}

	private void connectToVM(OutputStream client) throws UnknownHostException, IOException {
		System.out.println("Connecting to Input service daemon");
		inputService = new Socket(VM_ADDRESS, INPUT_SERVICE_PORT);
		inputServiceOut = inputService.getOutputStream();
		inputServiceIn  = inputService.getInputStream();

		System.out.println("Sending VIDEO_PARAMS to VM");
		Request.newBuilder().setType(RequestType.VIDEO_PARAMS)
				.setVideoInfo(makeVideoChannelInfo()).build()
				.writeDelimitedTo(inputServiceOut);

		System.out.println("Waiting for VM to be ready");
		Response resp = Response.parseDelimitedFrom(inputServiceIn);
		if (resp.getType() != ResponseType.VMREADY)
			throw new IOException("Expecting VMREADY from VM, but got: " + resp.getType().name());

		System.out.println("Input service daemon connected. Starting listen thread.");
		inputServiceThread = new InputServiceResponseHandler(client, inputServiceIn);
		inputServiceThread.start();
	}
	
	private VideoStreamInfo makeVideoChannelInfo() {
		final String iceServers = "{ \"iceServers\" : [ { \"url\" : \"stun:"
				+ STUN_SERVER + "\" } ] }";
		final String videoConstraints = "{ \"audio\" : true , \"video\" : { \"mandatory\" : {}, \"optional\" : []} }";
		final String pcConstraints = "{ \"optional\" : [ { \"DtlsSrtpKeyAgreement\" : true } ] }";

		VideoStreamInfo.Builder vidInfo = VideoStreamInfo.newBuilder();
		vidInfo.setIceServers(iceServers);
		vidInfo.setPcConstraints(pcConstraints);
		vidInfo.setVideoConstraints(videoConstraints);

//		return Response.newBuilder().setType(ResponseType.VIDSTREAMINFO)
//				.setVideoInfo(vidInfo).build();

		return vidInfo.build();
	}

    public void cleanup() {
        // close the connection to the client
        try {
            if (session != null && !session.isClosed())
                session.close();
        } catch (IOException e) {
            // do nothing
        }
        // close the connection to the VM
        try {
		if (inputServiceThread != null)
			inputServiceThread.stop();
	        if (inputService != null && !inputService.isClosed())
	            inputService.close();
        } catch (IOException e) {
            // do nothing
        }
    }
		
	private class InputServiceResponseHandler extends Thread {
		private OutputStream toClient;
		private InputStream fromService;

		private InputServiceResponseHandler(OutputStream client, InputStream service) {
			toClient = client;
			fromService = service;
		}

		@Override
		public void run() {
			try {
				while (true) {
					Response r = Response.parseDelimitedFrom(fromService);
					System.out.println("Sending response back to client: " + r.getType().name());

					debugDownstream(r);

					synchronized (toClient) {
						r.writeDelimitedTo(toClient);
					}
				}
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

	// Debug print outs for incoming messages from the client
	private void debugUpstream(Request req) {
		if (!DEBUG)
			return;

		// System.out.println("Request received: " + req.getType().name());
		// System.out.println("State = " + state.name());

		switch (req.getType()) {
		case SCREENINFO:
			break;
		case SENSOREVENT:
//			if (req.hasSensor()) {
//				System.out.print("Sensor type = "
//						+ req.getSensor().getType().name());
//				System.out.print(", Accuracy = "
//						+ req.getSensor().getAccuracy());
//				System.out.print(", Timestamp = "
//						+ req.getSensor().getTimestamp());
//				System.out.print(", Values = [");
//				int ctr = 0;
//				for (float v : req.getSensor().getValuesList()) {
//					if (ctr++ > 0)
//						System.out.print(", ");
//					System.out.print(v);
//				}
//				System.out.println("]");
//			}
			break;
		case TOUCHEVENT:
//			if (req.hasTouch()) {
//				System.out.println("Action = " + req.getTouch().getAction());
//				for (SVMPProtocol.TouchEvent.PointerCoords p : req.getTouch()
//						.getItemsList()) {
//					System.out.println("    id = " + p.getId() + " ; x = "
//							+ p.getX() + " ; y = " + p.getY());
//				}
//			}
			break;
		case INTENT:
			break;
//		case LOCATION:
//			if (req.hasLocationRequest()) {
//				SVMPProtocol.LocationRequest lr = req.getLocationRequest();
//				SVMPProtocol.LocationRequest.LocationRequestType type = lr
//						.getType();
//				String message = "";
//				switch (type) {
//				case PROVIDERINFO:
//					SVMPProtocol.LocationProviderInfo lpi = lr
//							.getProviderInfo();
//					message = String
//							.format("Location provider info: [provider '%s', reqNetwork '%b', "
//									+ "reqSat '%b', reqCell '%b', hasMonCost '%b', suppAlt '%b', suppSpeed '%b', "
//									+ "suppBearing '%b', powerReq '%d', accuracy '%d']",
//									lpi.getProvider(),
//									lpi.getRequiresNetwork(),
//									lpi.getRequiresSatellite(),
//									lpi.getRequiresCell(),
//									lpi.getHasMonetaryCost(),
//									lpi.getSupportsAltitude(),
//									lpi.getSupportsSpeed(),
//									lpi.getSupportsBearing(),
//									lpi.getPowerRequirement(),
//									lpi.getAccuracy());
//					break;
//				case PROVIDERSTATUS:
//					SVMPProtocol.LocationProviderStatus lps = lr
//							.getProviderStatus();
//					message = String
//							.format("Location provider enabled: [provider '%s', status '%d']",
//									lps.getProvider(), lps.getStatus());
//					break;
//				case PROVIDERENABLED:
//					SVMPProtocol.LocationProviderEnabled lpe = lr
//							.getProviderEnabled();
//					message = String
//							.format("Location provider enabled: [provider '%s', enabled '%b']",
//									lpe.getProvider(), lpe.getEnabled());
//					break;
//				case LOCATIONUPDATE:
//					SVMPProtocol.LocationUpdate lu = lr.getUpdate();
//					message = String
//							.format("Location update: [provider '%s', lat '%.2f', lon '%.2f', time '%s']",
//									lu.getProvider(), lu.getLatitude(),
//									lu.getLongitude(),
//									new Date(lu.getTime()).toString());
//					break;
//				}
//				System.out.println(message);
//			}
//			break;
		case WEBRTC:
			System.out.println("Request received: " + req.getType().name());
			System.out.println(req.getWebrtcMsg().getJson());
			break;
		default:
			System.out.println("Request received: " + req.getType().name());
			// System.out.println("State = " + state.name());
			break;
		}
	}

	// Debug print outs for incoming messages from the VM
	private void debugDownstream(Response r) {
		if (!DEBUG)
			return;

		System.out.println("Sending response back to client: "
				+ r.getType().name());

//		if (r.getType() == ResponseType.LOCATION) {
//			SVMPProtocol.LocationResponse lr = r.getLocationResponse();
//			String message = "";
//			switch (lr.getType()) {
//			case SUBSCRIBE:
//				SVMPProtocol.LocationSubscribe ls = lr.getSubscribe();
//				message = String.format(
//						"Location subscribe: [type '%s', provider '%s', minTime '%d', "
//								+ "minDist '%.2f']", ls.getType().name(),
//						ls.getProvider(), ls.getMinTime(), ls.getMinDistance());
//				break;
//			case UNSUBSCRIBE:
//				SVMPProtocol.LocationUnsubscribe lu = lr.getUnsubscribe();
//				message = String.format(
//						"Location unsubscribe: [provider '%s']",
//						lu.getProvider());
//				break;
//			}
//			System.out.println(message);
//		}

		if (r.getType() == ResponseType.WEBRTC) {
			System.out.println(r.getWebrtcMsg().getJson());
		}
	}
}
