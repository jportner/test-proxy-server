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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;

import org.mitre.svmp.protocol.SVMPProtocol;
import org.mitre.svmp.protocol.SVMPProtocol.Proxy;
import org.mitre.svmp.protocol.SVMPProtocol.Proxy.ServiceType;
import org.mitre.svmp.protocol.SVMPProtocol.Request;
import org.mitre.svmp.protocol.SVMPProtocol.Response;
import org.mitre.svmp.protocol.SVMPProtocol.Response.ResponseType;
import org.mitre.svmp.protocol.SVMPProtocol.ScreenInfo;

import com.google.protobuf.ByteString;
import com.google.protobuf.TextFormat;

/**
 * @author David Keppler <dkeppler@mitre.org>
 *
 */
public class TestProxy {

	public static String VM_ADDRESS = "192.168.43.100";
	public static int INPUT_SERVICE_PORT = 8001;
	public static int INTENT_SERVICE_PORT = 7777;
	public static String RTSP_URL = "rtsp://" + VM_ADDRESS + ":5544/rtsp.sdp";
	
	public static final int LISTEN_PORT = 8002;
	
	private static final int UNAUTHENTICATED = 0;
	private static final int AUTHENTICATED = 1;
	private static final int PROXYING = 2;

	private Socket inputService = null;
	private InputStream  inputServiceIn = null;
	private OutputStream inputServiceOut = null;
	private Thread inputServiceThread;

	private Socket intentService = null;
	private InputStream  intentServiceIn = null;
	private OutputStream intentServiceOut = null;
	private Thread intentServiceThread;
	
	private int state = UNAUTHENTICATED;
	
	Socket session;
	
	public TestProxy(Socket s) {
		session = s;
	}
	
	/**
	 * @param args
	 * @throws IOException 
	 * @throws InterruptedException 
	 */
	public static void main(String[] args) throws IOException, InterruptedException {
		ServerSocket daemon = new ServerSocket(LISTEN_PORT);
		System.out.println("Listen socket opened on port " + LISTEN_PORT);
		
		while (true) {
			TestProxy session = null;
			try {
				Socket s = daemon.accept();
				System.out.println("Client connection received from " + s.getInetAddress());
				session = new TestProxy(s);
				session.run();
			} catch (Exception e) {
				e.printStackTrace();
				if (session != null)
					session.cleanup();
			}
		}
	}
	
	private void run() throws IOException, InterruptedException {
		InputStream in = session.getInputStream();
		OutputStream out = session.getOutputStream();
		
		System.out.println("Starting listen loop");
		
		while (!session.isClosed()) {
			Request req = Request.parseDelimitedFrom(in);
			//System.out.println("Request received: " + req.getType().name());
			Response.Builder response = SVMPProtocol.Response.newBuilder();
			switch (state) {
			case UNAUTHENTICATED:
				if (doAuthentication(req)) {
					response.setType(ResponseType.AUTHOK);
					synchronized(out) {
						response.build().writeDelimitedTo(out);
						System.out.println("AUTHOK sent");
					}
					connectToVM(out);
					response.clear();
					System.out.println("Waiting for \"VM to start\"");
					Thread.sleep(2000); // pretend we have to wait a bit for the VM to connect
					response.setType(ResponseType.VMREADY);
					response.setMessage(RTSP_URL);
					state = PROXYING;
					synchronized(out) {
						response.build().writeDelimitedTo(out);
						System.out.println("VMREADY sent");
					}
				} else {
					response.setType(ResponseType.ERROR);
					response.setMessage("Authentication failed.");
					synchronized(out) {
						response.build().writeDelimitedTo(out);
						System.out.println("Authentication ERROR sent");
					}
					// failed or unexpected message type
				}
				break;
			case AUTHENTICATED:
				break;
			case PROXYING:
				switch(req.getType()) {
				case SCREENINFO:
					/*
					response.clear();
		        	ScreenInfo.Builder scr = SVMPProtocol.ScreenInfo.newBuilder();
		        	scr.setX(360);
		        	scr.setY(480);
		        	response.setType(ResponseType.SCREENINFO);
		        	response.setScreenInfo(scr);
		        	response.build().writeDelimitedTo(out);
		        	break;
		        	*/
				case SENSOREVENT:
					/*
					if (req.hasSensor()) {
						System.out.println("Sensor type = " + req.getSensor().getType().name());
						System.out.println("   Accuracy = " + req.getSensor().getAccuracy());
						System.out.println("   Timestamp = " + req.getSensor().getTimestamp());
						System.out.print("   Values = [");
						for (float v : req.getSensor().getValuesList()) {
							System.out.print(" "+v);
						}
						System.out.println("]");
					}
					*/
				case TOUCHEVENT:
					/*
					if (req.hasTouch()) {
						System.out.println("Action = " + req.getTouch().getAction());
						for (SVMPProtocol.TouchEvent.PointerCoords p : req.getTouch().getItemsList()) {
							System.out.println("    id = " + p.getId() + " ; x = " + p.getX() + " ; y = " + p.getY());
						}
					}
					*/
					req.writeDelimitedTo(inputServiceOut);
					//System.out.println("Request forwarded to input server");
					break;
				case INTENT:
					// not yet implemented
					break;
				case LOCATION:
					// not yet implemented
					break;
				case RAWINPUTPROXY:
					if (req.hasProxy()) {
						System.out.println("Forwarding data to VM daemons");
						switch (req.getProxy().getType()) {			
						case INPUT:
							inputServiceOut.write(req.getProxy().getData().toByteArray());
							break;
						case INTENT:
							intentServiceOut.write(req.getProxy().getData().toByteArray());
							break;
						}
					}
					break;
				}

				break;	// PROXYING state
			}
		}
	}
	
	private boolean doAuthentication(SVMPProtocol.Request r) {
		if (r.hasAuthentication())
			return true;
		else
			return false;
	}

	private void connectToVM(OutputStream client) throws UnknownHostException, IOException {
		System.out.println("Connecting to Input service daemon");
		inputService = new Socket(VM_ADDRESS, INPUT_SERVICE_PORT);
		inputServiceOut = inputService.getOutputStream();
		inputServiceIn  = inputService.getInputStream();
		inputServiceThread = new InputServiceResponseHandler(client, inputServiceIn);
		System.out.println("Input service daemon connected. Starting listen thread.");
		inputServiceThread.start();
/*
		System.out.println("Connecting to Intent service daemon");		
		intentService = new Socket(VM_ADDRESS, INTENT_SERVICE_PORT);
		intentServiceOut = intentService.getOutputStream();
		intentServiceIn  = intentService.getInputStream();
		intentServiceThread = new ProxyResponseHandler(ServiceType.INTENT, client, intentServiceIn);
		System.out.println("Intent service daemon connected. Starting listen thread.");
		intentServiceThread.start();
*/
	}

	public void cleanup() throws IOException {
		inputServiceThread.stop();
		//intentServiceThread.stop();
		inputService.close();
		//intentService.close();
	}
	
	private class ProxyResponseHandler extends Thread {
		private OutputStream toClient;
		private InputStream fromService;
		private ServiceType type;
		
		private ProxyResponseHandler(ServiceType servicetype, OutputStream client, InputStream service) {
			toClient = client;
			fromService = service;
			type = servicetype;
		}

		@Override
		public void run() {
			Response.Builder response = SVMPProtocol.Response.newBuilder();
			Proxy.Builder proxy = SVMPProtocol.Proxy.newBuilder();
			byte[] data = new byte[512];
			while (true) {
				int b = -1;
				try {
					b = fromService.read(data, 0, data.length);
				} catch (IOException e) {
					e.printStackTrace();
					break;
				}
				if (b < 0) break;
				if (b > 0) {
					response.clear();
					proxy.clear();
					proxy.setType(type);
					proxy.setData(ByteString.copyFrom(data, 0, b));
					if (type == ServiceType.INPUT)
						response.setType(ResponseType.SCREENINFO);
					else if (type == ServiceType.INTENT)
						response.setType(ResponseType.INTENT);
					response.setProxy(proxy);
					synchronized(toClient) {
						try {
							System.out.println("Sending wrapped daemon data back to client");
							response.build().writeDelimitedTo(toClient);
						} catch (IOException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
							return;
						}
					}
				}
			}
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
}
