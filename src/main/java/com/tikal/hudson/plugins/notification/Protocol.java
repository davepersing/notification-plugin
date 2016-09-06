/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.tikal.hudson.plugins.notification;


import java.io.IOException;

import java.io.OutputStream;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.spec.SecretKeySpec;

import javax.crypto.Mac;
import javax.xml.bind.DatatypeConverter;

public enum Protocol {

    UDP {
        @Override
        protected void send(String url, byte[] data, int timeout, boolean isJson, String secretKey) throws IOException {
            HostnamePort hostnamePort = HostnamePort.parseUrl(url);
            DatagramSocket socket = new DatagramSocket();
            DatagramPacket packet = new DatagramPacket(data, data.length, InetAddress.getByName(hostnamePort.hostname), hostnamePort.port);
            socket.send(packet);
        }
    },
    TCP {
        @Override
        protected void send(String url, byte[] data, int timeout, boolean isJson, String secretKey) throws IOException {
            HostnamePort hostnamePort = HostnamePort.parseUrl(url);
            SocketAddress endpoint = new InetSocketAddress(InetAddress.getByName(hostnamePort.hostname), hostnamePort.port);
            Socket socket = new Socket();
            socket.setSoTimeout(timeout);
            socket.connect(endpoint, timeout);
            OutputStream output = socket.getOutputStream();
            output.write(data);
            output.flush();
            output.close();
        }
    },
    HTTP {
        @Override
        protected void send(String url, byte[] data, int timeout, boolean isJson, String secretKey) throws IOException {
            URL targetUrl = new URL(url);
            if (!targetUrl.getProtocol().startsWith("http")) {
              throw new IllegalArgumentException("Not an http(s) url: " + url);
            }

            // Verifying if the HTTP_PROXY is available
            final String httpProxyUrl = System.getenv().get("http_proxy");
            URL proxyUrl = null;
            if (httpProxyUrl != null && httpProxyUrl.length() > 0) {
              proxyUrl = new URL(httpProxyUrl);
              if (!proxyUrl.getProtocol().startsWith("http")) {
                throw new IllegalArgumentException("Not an http(s) url: " + httpProxyUrl);
              }
            }

            HttpURLConnection connection = null;
            if (proxyUrl == null) {
              connection = (HttpURLConnection) targetUrl.openConnection();

            } else {
              // Proxy connection to the address provided
              final int proxyPort = proxyUrl.getPort() > 0 ? proxyUrl.getPort() : 80;
              Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyUrl.getHost(), proxyPort));
              connection = (HttpURLConnection) targetUrl.openConnection(proxy);
            }

            connection.setRequestProperty("Content-Type", String.format( "application/%s;charset=UTF-8", isJson ? "json" : "xml" ));
            String userInfo = targetUrl.getUserInfo();
            if (null != userInfo) {
              String b64UserInfo = DatatypeConverter.printBase64Binary(userInfo.getBytes());
              String authorizationHeader = "Basic " + b64UserInfo;
              connection.setRequestProperty("Authorization", authorizationHeader);
            }
            
            // Create authorization header
            if (!isEmpty(secretKey)) {
            	String strData = new String(data);
            	String signature = createSignature(strData, secretKey);
            	String authorizationHeader = "Bearer " + signature;
            	connection.setRequestProperty("Authorization", authorizationHeader);
            }
            
            connection.setFixedLengthStreamingMode(data.length);
            connection.setDoInput(true);
            connection.setDoOutput(true);
            connection.setConnectTimeout(timeout);
            connection.setReadTimeout(timeout);
            connection.connect();
            try {
              OutputStream output = connection.getOutputStream();
              try {
                output.write(data);
                output.flush();
              } finally {
                output.close();
              }
            } finally {
              // Follow an HTTP Temporary Redirect if we get one,
              //
              // NB: Normally using the HttpURLConnection interface, we'd call
              // connection.setInstanceFollowRedirects(true) to enable 307 redirect following but
              // since we have the connection in streaming mode this does not work and we instead
              // re-direct manually.
              if (307 == connection.getResponseCode()) {
                String location = connection.getHeaderField("Location");
                connection.disconnect();
                send(location, data,timeout, isJson, secretKey);
              } else {
                connection.disconnect();
              }
            }
        }

        @Override
        public void validateUrl( String url ) {
            try {
                // noinspection ResultOfObjectAllocationIgnored
                new URL( url );
            } catch ( MalformedURLException e ) {
                throw new RuntimeException( String.format( "%sUse http://hostname:port/path for endpoint URL",
                                                           isEmpty ( url ) ? "" : "Invalid URL '" + url + "'. " ));
            }
        }
    };


    protected abstract void send(String url, byte[] data, int timeout, boolean isJson, String secretKey) throws IOException;

    private static String createSignature(String payload, String secretKey) {
    	String digest = null;
		try {
			Mac mac = null;
			mac = Mac.getInstance("HmacSHA1");
	
	    	SecretKeySpec secret = new SecretKeySpec(secretKey.getBytes(), "HmacSHA1");
	    	mac.init(secret);
	    	byte[] bytes = mac.doFinal(payload.getBytes());
	    	BigInteger hash = new BigInteger(1, bytes);
	    	digest = hash.toString(16);
	    	
	    	if (digest.length() % 2 != 0) {
	    		digest = "0" + digest;
	    	}
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
    	return digest;
    }
    
    public void validateUrl(String url) {
        try {
            HostnamePort hnp = HostnamePort.parseUrl(url);
            if (hnp == null) {
                throw new Exception();
            }
        } catch (Exception e) {
            throw new RuntimeException( String.format( "%sUse hostname:port for endpoint URL",
                                                       isEmpty ( url ) ? "" : "Invalid URL '" + url + "'. " ));
        }
    }

    private static boolean isEmpty( String s ) {
        return (( s == null ) || ( s.trim().length() < 1 ));
    }
}
