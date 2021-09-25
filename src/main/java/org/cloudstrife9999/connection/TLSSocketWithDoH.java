package org.cloudstrife9999.connection;

import java.io.IOException;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.cloudstrife9999.dns.Doh;

public class TLSSocketWithDoH {
    
    private TLSSocketWithDoH() {}

    public static SSLSocket connect(String domainName) throws IOException {
        return TLSSocketWithDoH.connect(domainName, 443, true); // Using IPv6 by default, if available.
    }

    public static SSLSocket connect(String domainName, int port) throws IOException {
        return TLSSocketWithDoH.connect(domainName, port, true); // Using IPv6 by default, if available.
    }
    
    public static SSLSocket connect(String domainName, boolean preferIPv6IfAvailable) throws IOException {
        return TLSSocketWithDoH.connect(domainName, 443, preferIPv6IfAvailable);
    }

    public static SSLSocket connect(String domainName, int port, boolean preferIPv6IfAvailable) throws IOException {
        Doh client = new Doh();

        if(preferIPv6IfAvailable) {
            List<String> results = client.resIPv6(domainName);

            if(results.isEmpty()) {
                return TLSSocketWithDoH.connect(domainName, 443, false);
            }
            else {
                return TLSSocketWithDoH.getSocketWithSNI(results.get(0), domainName, port);
            }
        }
        else {
            List<String> results = client.resIPv4(domainName);

            if(results.isEmpty()) {
                throw new IOException("No DNS resolution was possible for the domain name " + domainName + " .");
            }
            else {
                return TLSSocketWithDoH.getSocketWithSNI(results.get(0), domainName, port);
            }
        }
    }

    private static SSLSocket getSocketWithSNI(String ip, String domainName, int port) throws IOException {
        SSLParameters parameters = new SSLParameters();
            
        parameters.setServerNames(Arrays.asList(new SNIHostName(domainName)));

        TLSSocketFactoryWithSNI factory = new TLSSocketFactoryWithSNI((SSLSocketFactory) SSLSocketFactory.getDefault(), parameters);
        
        return (SSLSocket) factory.createSocket(InetAddress.getByName(ip), port);
    }
}
