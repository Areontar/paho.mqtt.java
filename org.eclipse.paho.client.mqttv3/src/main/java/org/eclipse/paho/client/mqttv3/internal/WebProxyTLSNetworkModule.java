package org.eclipse.paho.client.mqttv3.internal;

import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.logging.Logger;
import org.eclipse.paho.client.mqttv3.logging.LoggerFactory;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

public class WebProxyTLSNetworkModule implements NetworkModule {

    private static final String CLASS_NAME = WebProxyTLSNetworkModule.class.getName();
    private Logger log = LoggerFactory.getLogger(LoggerFactory.MQTT_CLIENT_MSG_CAT,CLASS_NAME);

    private final SSLSocketFactory socketFactory;
    private final String host;
    private final int port;
    private final String webproxyHost;
    private final int webproxyPort;
    private final String resourceContext;

    private SSLSocket sslSocket;
    private int handshakeTimeoutSecs;
    private int conTimeout;
    private String[] enabledCiphers;
    private HostnameVerifier hostnameVerifier;
    private boolean httpsHostnameVerificationEnabled;



    public WebProxyTLSNetworkModule(SSLSocketFactory socketFactory, String host, int port, String webproxyHost, int webproxyPort, String resourceContext) {
        this(socketFactory, host, port, webproxyHost, webproxyPort, resourceContext, null);
    }

    public WebProxyTLSNetworkModule(SSLSocketFactory socketFactory, String host, int port, String webproxyHost, int webproxyPort, String resourceContext, String[] enabledCiphers) {
        log.setResourceName(resourceContext);
        this.socketFactory = socketFactory;
        this.host = host;
        this.port = port;
        this.webproxyHost = webproxyHost;
        this.webproxyPort = webproxyPort;
        this.resourceContext = resourceContext;
        this.enabledCiphers = enabledCiphers;
    }

    /**
     * Returns the enabled cipher suites.
     *
     * @return a string array of enabled Cipher suites
     */
    public String[] getEnabledCiphers() {
        return enabledCiphers;
    }

    /**
     * Sets the enabled cipher suites on the underlying network socket.
     *
     * @param enabledCiphers
     *            a String array of cipher suites to enable
     */
    private void setEnabledCiphers(String[] enabledCiphers) {
        final String methodName = "setEnabledCiphers";
        if (enabledCiphers != null) {
            this.enabledCiphers = enabledCiphers.clone();
        }
        if ((sslSocket != null) && (this.enabledCiphers != null)) {
            if (log.isLoggable(Logger.FINE)) {
                String ciphers = "";
                for (int i = 0; i < this.enabledCiphers.length; i++) {
                    if (i > 0) {
                        ciphers += ",";
                    }
                    ciphers += this.enabledCiphers[i];
                }
                // @TRACE 260=setEnabledCiphers ciphers={0}
                log.fine(CLASS_NAME, methodName, "260", new Object[] { ciphers });
            }
            ((SSLSocket) sslSocket).setEnabledCipherSuites(this.enabledCiphers);
        }
    }

    public void setSSLhandshakeTimeout(int timeout) {
        setConnectTimeout(timeout);
        this.handshakeTimeoutSecs = timeout;
    }

    /**
     * Set the maximum time to wait for a socket to be established
     * @param timeout  The connection timeout
     */
    private void setConnectTimeout(int timeout) {
        this.conTimeout = timeout;
    }

    public HostnameVerifier getSSLHostnameVerifier() {
        return hostnameVerifier;
    }

    public void setSSLHostnameVerifier(HostnameVerifier hostnameVerifier) {
        this.hostnameVerifier = hostnameVerifier;
    }

    public boolean isHttpsHostnameVerificationEnabled() {
        return httpsHostnameVerificationEnabled;
    }

    public void setHttpsHostnameVerificationEnabled(boolean httpsHostnameVerificationEnabled) {
        this.httpsHostnameVerificationEnabled = httpsHostnameVerificationEnabled;
    }

    public void start() throws IOException, MqttException {
        final String methodName = "start";
        Socket tunnel = new Socket(webproxyHost, webproxyPort);
        doTunnelHandshake(tunnel, host, port);

        sslSocket = (SSLSocket) socketFactory.createSocket(tunnel, host, port, true);

        sslSocket.addHandshakeCompletedListener(new HandshakeCompletedListener() {

            public void handshakeCompleted(HandshakeCompletedEvent event) {
                log.fine(CLASS_NAME,methodName, "252", new Object[] {host, Integer.valueOf(port)});
            }
        });

        setEnabledCiphers(enabledCiphers);
        int soTimeout = sslSocket.getSoTimeout();
        // RTC 765: Set a timeout to avoid the SSL handshake being blocked indefinitely
        sslSocket.setSoTimeout(this.handshakeTimeoutSecs * 1000);

        // SNI support.  Should be automatic under some circumstances - not all, apparently
        SSLParameters sslParameters = new SSLParameters();
        List<SNIServerName> sniHostNames = new ArrayList<SNIServerName>(1);
        sniHostNames.add(new SNIHostName(host));
        sslParameters.setServerNames(sniHostNames);
        ((SSLSocket)sslSocket).setSSLParameters(sslParameters);

        // If default Hostname verification is enabled, use the same method that is used with HTTPS
        if(this.httpsHostnameVerificationEnabled) {
            SSLParameters sslParams = new SSLParameters();
            sslParams.setEndpointIdentificationAlgorithm("HTTPS");
            sslSocket.setSSLParameters(sslParams);
        }
        sslSocket.startHandshake();
        if (hostnameVerifier != null && !this.httpsHostnameVerificationEnabled) {
            SSLSession session = sslSocket.getSession();
            if(!hostnameVerifier.verify(host, session)) {
                session.invalidate();
                sslSocket.close();
                throw new SSLPeerUnverifiedException("Host: " + host + ", Peer Host: " + session.getPeerHost());
            }
        }
        // reset timeout to default value
        sslSocket.setSoTimeout(soTimeout);
    }

    public InputStream getInputStream() throws IOException {
        return sslSocket.getInputStream();
    }

    public OutputStream getOutputStream() throws IOException {
        return sslSocket.getOutputStream();
    }

    public void stop() throws IOException {
        sslSocket.close();
    }

    public String getServerURI() {
        return "wp://" + host + ":" + port;
    }

    /*
     * Tell our tunnel where we want to CONNECT, and look for the right reply. Throw
     * IOException if anything goes wrong.
     */
    private void doTunnelHandshake(Socket tunnel, String host, int port) throws IOException {
        String methodName = "doTunnelHandshake";
        log.fine(CLASS_NAME,methodName, "253", new Object[] {host, Integer.valueOf(port)});

        OutputStream out = tunnel.getOutputStream();
        String msg = "CONNECT " + host + ":" + port + " HTTP/1.0\n" + "User-Agent: " + "agent" + "\r\n\r\n";
        byte b[];
        try {
            b = msg.getBytes("ASCII7");
        } catch (UnsupportedEncodingException ignored) {
            b = msg.getBytes();
        }
        out.write(b);
        out.flush();

        byte reply[] = new byte[200];
        int replyLen = 0;
        int newlinesSeen = 0;
        boolean headerDone = false;

        InputStream in = tunnel.getInputStream();
        boolean error = false;

        while (newlinesSeen < 2) {
            int i = in.read();
            if (i < 0) {
                throw new IOException("Unexpected EOF from proxy");
            }
            if (i == '\n') {
                headerDone = true;
                ++newlinesSeen;
            } else if (i != '\r') {
                newlinesSeen = 0;
                if (!headerDone && replyLen < reply.length) {
                    reply[replyLen++] = (byte) i;
                }
            }
        }

        String replyStr;
        try {
            replyStr = new String(reply, 0, replyLen, "ASCII7");
        } catch (UnsupportedEncodingException ignored) {
            replyStr = new String(reply, 0, replyLen);
        }

        if (!replyStr.startsWith("HTTP/1.0 200")) {
            log.fine(CLASS_NAME,methodName, "254", new Object[] {host, Integer.valueOf(port), replyStr});
        }
    }
}
