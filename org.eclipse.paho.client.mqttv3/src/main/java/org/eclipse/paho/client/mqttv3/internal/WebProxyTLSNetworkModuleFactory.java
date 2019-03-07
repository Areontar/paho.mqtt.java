package org.eclipse.paho.client.mqttv3.internal;

import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.internal.security.SSLSocketFactoryFactory;
import org.eclipse.paho.client.mqttv3.spi.NetworkModuleFactory;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.net.URI;
import java.util.*;

public class WebProxyTLSNetworkModuleFactory implements NetworkModuleFactory {


    /**
     * here we have to invent a scheme since Paho choose the factory based on the supported scheme. since the first one is selected, its difficult to
     * make sure we can route traffic throught the webproxy vs straight trought connection
     * @return
     */
    public Set<String> getSupportedUriSchemes() {
        return Collections.unmodifiableSet(new HashSet(Arrays.asList("wp")));
    }

    public void validateURI(URI brokerUri) throws IllegalArgumentException {
        String path = brokerUri.getPath();
        if (path != null && !path.isEmpty()) {
            throw new IllegalArgumentException(brokerUri.toString());
        }
    }

    public NetworkModule createNetworkModule(URI brokerUri, MqttConnectOptions options, String clientId) throws MqttException {
        String host = brokerUri.getHost();
        int port = brokerUri.getPort(); // -1 if not defined
        if (port == -1) {
            port = 8883;
        }
        String path = brokerUri.getPath();
        if (path != null && !path.isEmpty()) {
            throw new IllegalArgumentException(brokerUri.toString());
        }

        String webproxyHost = options.getWebproxyURI().getHost();
        int webproxyPort = options.getWebproxyURI().getPort(); // -1 if not defined
        String weproxypath = options.getWebproxyURI().getPath();
        if (weproxypath != null && !weproxypath.isEmpty()) {
            throw new IllegalArgumentException(brokerUri.toString());
        }

        SocketFactory factory = options.getSocketFactory();
        SSLSocketFactoryFactory factoryFactory = null;
        if (factory == null) {
=            factoryFactory = new SSLSocketFactoryFactory();
            Properties sslClientProps = options.getSSLProperties();
            if (null != sslClientProps) {
                factoryFactory.initialize(sslClientProps, null);
            }
            factory = factoryFactory.createSocketFactory(null);
        } else if ((factory instanceof SSLSocketFactory) == false) {
            throw ExceptionHelper.createMqttException(MqttException.REASON_CODE_SOCKET_FACTORY_MISMATCH);
        }

        // Create the network module...

        String[] enabledCiphers = null;
        // Ciphers suites need to be set, if they are available
        if (factoryFactory != null) {
            enabledCiphers = factoryFactory.getEnabledCipherSuites(null);
        }

        WebProxyTLSNetworkModule netModule = new WebProxyTLSNetworkModule((SSLSocketFactory) factory, host, port, webproxyHost, webproxyPort, clientId, enabledCiphers);
        netModule.setSSLhandshakeTimeout(options.getConnectionTimeout());
        netModule.setSSLHostnameVerifier(options.getSSLHostnameVerifier());
        netModule.setHttpsHostnameVerificationEnabled(options.isHttpsHostnameVerificationEnabled());

        return netModule;
    }
}
