package org.cloudstrife9999.connection;

import java.io.IOException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocketFactory;

import org.cloudstrife9999.dns.Doh;

public class HttpsConnectionWithDoH {

    private HttpsConnectionWithDoH() {}

    public static HttpsURLConnection connectAfterResolvingViaDoH(String domainName, String subresource) throws IOException {
        return HttpsConnectionWithDoH.connectAfterResolvingViaDoH(domainName, 443, subresource, true); // Using IPv6 by default, if available.
    }

    public static HttpsURLConnection connectAfterResolvingViaDoH(String domainName, String subresource, boolean preferIPv6IfAvailable) throws IOException {
        return HttpsConnectionWithDoH.connectAfterResolvingViaDoH(domainName, 443, subresource, preferIPv6IfAvailable);
    }

    public static HttpsURLConnection connectAfterResolvingViaDoH(String domainName, int port, String subresource) throws IOException {
        return HttpsConnectionWithDoH.connectAfterResolvingViaDoH(domainName, port, subresource, true); // Using IPv6 by default, if available.
    }

    public static HttpsURLConnection connectAfterResolvingViaDoH(String domainName, int port, String subresource, boolean preferIPv6IfAvailable) throws IOException {
        Doh client = new Doh();

        if(preferIPv6IfAvailable) {
            List<String> results = client.resIPv6(domainName);

            if(results.isEmpty()) {
                return HttpsConnectionWithDoH.connectAfterResolvingViaDoH(domainName, port, subresource, false);
            }
            else {
                return HttpsConnectionWithDoH.openConnection(results.get(0), domainName, port, subresource);
            }
        }
        else {
            List<String> results = client.resIPv4(domainName);

            if(results.isEmpty()) {
                throw new IOException("No DNS resolution was possible for the domain name " + domainName + " .");
            }
            else {
                return HttpsConnectionWithDoH.openConnection(results.get(0), domainName, port, subresource);
            }
        }
    }

    public static HttpsURLConnection openConnection(String ip, String domainName, int port, String subresource) throws IOException {
        try {
            if(ip.contains(":")) {
                ip = "[" + ip + "]";
            }

            SSLParameters parameters = new SSLParameters();
            
            parameters.setServerNames(Arrays.asList(new SNIHostName(domainName)));
    
            TLSSocketFactoryWithSNI factory = new TLSSocketFactoryWithSNI((SSLSocketFactory) SSLSocketFactory.getDefault(), parameters);
            HttpsURLConnection.setDefaultSSLSocketFactory(factory);

            URL url = new URL("https://" + ip + ":" + port + "/" + subresource);

            return (HttpsURLConnection) url.openConnection();
        }
        catch(IOException e) {
            throw e;
        }
        catch(Exception e) {
            throw new IllegalArgumentException(e);
        }
    }
}
