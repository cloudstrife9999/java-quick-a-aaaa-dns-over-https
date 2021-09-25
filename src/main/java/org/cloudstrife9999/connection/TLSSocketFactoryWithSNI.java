package org.cloudstrife9999.connection;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class TLSSocketFactoryWithSNI extends SSLSocketFactory {
    private final SSLSocketFactory wrappedFactory;
    private final SSLParameters tlsParameters;

    public TLSSocketFactoryWithSNI(SSLSocketFactory factory, SSLParameters tlsParameters) {
        this.wrappedFactory = factory;
        this.tlsParameters = tlsParameters;
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        SSLSocket socket = (SSLSocket) wrappedFactory.createSocket(s, host, port, autoClose);

        setParameters(socket);
        
        return socket;
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return this.wrappedFactory.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
       return this.wrappedFactory.getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        SSLSocket socket = (SSLSocket) wrappedFactory.createSocket(host, port);

        setParameters(socket);

        return socket;
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        SSLSocket socket = (SSLSocket) wrappedFactory.createSocket(host, port);

        setParameters(socket);

        return socket;
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
        SSLSocket socket = (SSLSocket) wrappedFactory.createSocket(host, port, localHost, localPort);

        setParameters(socket);

        return socket;
    }

    @Override
    public Socket createSocket(InetAddress host, int port, InetAddress localHost, int localPort) throws IOException {
        SSLSocket socket = (SSLSocket) wrappedFactory.createSocket(host, port, localHost, localPort);

        setParameters(socket);

        return socket;
    }

    @Override
    public Socket createSocket() throws IOException {
        SSLSocket socket = (SSLSocket) wrappedFactory.createSocket();

        setParameters(socket);

        return socket;
    }
 
    private void setParameters(SSLSocket socket) {
        socket.setSSLParameters(this.tlsParameters);
    }
}
