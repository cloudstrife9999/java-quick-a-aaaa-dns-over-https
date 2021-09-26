package org.cloudstrife9999.connection;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.cloudstrife9999.dns.DNSOverHTTPSResolver;

public class TLSSocketFactoryWithDoHAndSNI extends SSLSocketFactory {
    private SSLSocketFactory wrapped;
    private String domainNameToResolve;
    private static TLSSocketFactoryWithDoHAndSNI instance;

    private TLSSocketFactoryWithDoHAndSNI(String domainNameToResolve) {
        this.wrapped = (SSLSocketFactory) SSLSocketFactory.getDefault();
        this.domainNameToResolve = domainNameToResolve;
    }

    public static TLSSocketFactoryWithDoHAndSNI getInstance(String domainNameToResolve) {
        if (domainNameToResolve == null) {
            throw new IllegalArgumentException("Invalid hostname: " + domainNameToResolve);
        }
        else if(TLSSocketFactoryWithDoHAndSNI.instance == null || TLSSocketFactoryWithDoHAndSNI.instance.domainNameToResolve == null || !TLSSocketFactoryWithDoHAndSNI.instance.domainNameToResolve.equals(domainNameToResolve)) {
            TLSSocketFactoryWithDoHAndSNI.instance = new TLSSocketFactoryWithDoHAndSNI(domainNameToResolve);
        }

        return TLSSocketFactoryWithDoHAndSNI.instance;
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        if(host == null || !host.equals(this.domainNameToResolve)) {
            throw new IllegalArgumentException(this.constructHostMismatchMessage(host));
        }

        return this.createSocket(s, host, port, autoClose, true); // Attempting an IPv6 resolution by default first.
    }

    public Socket createSocket(Socket s, String host, int port, boolean autoClose, boolean preferIPv6IfAvailable) throws IOException {
        if(host == null || !host.equals(this.domainNameToResolve)) {
            throw new IllegalArgumentException(this.constructHostMismatchMessage(host));
        }
        
        String ipAddress = this.resolveDomainNameWithDoH(host, preferIPv6IfAvailable);

        SSLParameters tlsParameters = this.generateTLSParametersWithSNI(host);
        SSLSocket socket = (SSLSocket) this.wrapped.createSocket(s, ipAddress, port, autoClose);

        socket.setSSLParameters(tlsParameters);
        
        return socket;
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return this.wrapped.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return this.wrapped.getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        if(host == null || !host.equals(this.domainNameToResolve)) {
            throw new IllegalArgumentException(this.constructHostMismatchMessage(host));
        }
        
        return this.createSocket(host, port, true); // Attempting an IPv6 resolution by default first.
    }

    public Socket createSocket(String host, int port, boolean preferIPv6IfAvailable) throws IOException {
        if(host == null || !host.equals(this.domainNameToResolve)) {
            throw new IllegalArgumentException(this.constructHostMismatchMessage(host));
        }
        
        String ipAddress = this.resolveDomainNameWithDoH(host, preferIPv6IfAvailable);

        SSLParameters tlsParameters = this.generateTLSParametersWithSNI(host);
        SSLSocket socket = (SSLSocket) this.wrapped.createSocket(ipAddress, port);

        socket.setSSLParameters(tlsParameters);
        
        return socket;
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        SSLParameters tlsParameters = this.generateTLSParametersWithSNI(this.domainNameToResolve);
        SSLSocket socket = (SSLSocket) this.wrapped.createSocket(host, port); // Nothing to resolve here: we already get a remote IP address.

        socket.setSSLParameters(tlsParameters);
        
        return socket;
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
        return this.createSocket(host, port, localHost, localPort, true); // Attempting an IPv6 resolution by default first.
    }

    public Socket createSocket(String host, int port, InetAddress localHost, int localPort, boolean preferIPv6IfAvailable) throws IOException {
        if(host == null || !host.equals(this.domainNameToResolve)) {
            throw new IllegalArgumentException(this.constructHostMismatchMessage(host));
        }
        
        String ipAddress = this.resolveDomainNameWithDoH(host, preferIPv6IfAvailable);

        SSLParameters tlsParameters = this.generateTLSParametersWithSNI(host);
        SSLSocket socket = (SSLSocket) this.wrapped.createSocket(ipAddress, port, localHost, localPort);

        socket.setSSLParameters(tlsParameters);
        
        return socket;
    }

    @Override
    public Socket createSocket(InetAddress host, int port, InetAddress localHost, int localPort) throws IOException {
        SSLParameters tlsParameters = this.generateTLSParametersWithSNI(this.domainNameToResolve);
        SSLSocket socket = (SSLSocket) this.wrapped.createSocket(host, port, localHost, localPort); // Nothing to resolve here: we already get a remote IP address.

        socket.setSSLParameters(tlsParameters);
        
        return socket;
    }

    /**
     * 
     * WARNING: this assumes the caller sets (afterwards) a hostname that is compatible with the domain name specified in the SNI.<br/><br/>
     * 
     * If that is not the case, the behaviour is unspecified.
     * 
     */
    @Override
    public Socket createSocket() throws IOException {
        SSLParameters tlsParameters = this.generateTLSParametersWithSNI(this.domainNameToResolve);
        SSLSocket socket = (SSLSocket) this.wrapped.createSocket(); // Nothing to resolve here.

        socket.setSSLParameters(tlsParameters);
        
        return socket;
    }
    
    private SSLParameters generateTLSParametersWithSNI(String domainName) {
        SSLParameters parameters = new SSLParameters();
            
        parameters.setServerNames(Arrays.asList(new SNIHostName(domainName)));

        return parameters;
    }

    private String resolveDomainNameWithDoH(String domainName, boolean preferIPv6IfAvailable) throws IOException {
        DNSOverHTTPSResolver client = new DNSOverHTTPSResolver();

        if(preferIPv6IfAvailable) {
            List<String> results = client.resolveToIPv6(domainName);

            if(results.isEmpty()) {
                return this.resolveDomainNameWithDoH(domainName, false);
            }
            else {
                return results.get(0);
            }
        }
        else {
            List<String> results = client.resolveToIPv4(domainName);

            if(results.isEmpty()) {
                throw new IOException("No DNS resolution was possible for the domain name " + domainName + " .");
            }
            else {
                return results.get(0);
            }
        }
    }

    private String constructHostMismatchMessage(String providedHostname) {
        return "No match between the provided host (" + providedHostname + ") and the host declared upon creation of the factory (" + this.domainNameToResolve + ").";
    }
}
