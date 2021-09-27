package org.cloudstrife9999.connection;

import java.io.IOException;
import java.net.URL;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;

import org.cloudstrife9999.dns.DNSOverHTTPSResolver;

public class HttpsConnectionWithDoHAndSNI {

    private HttpsConnectionWithDoHAndSNI() {}

    public static HttpsURLConnection connectAfterResolvingViaDoH(String domainName, String subresource) throws IOException {
        return HttpsConnectionWithDoHAndSNI.connectAfterResolvingViaDoH(domainName, 443, subresource, null, true); // Using IPv6 by default, if available.
    }

    public static HttpsURLConnection connectAfterResolvingViaDoH(String domainName, String subresource, String customUserAgent) throws IOException {
        return HttpsConnectionWithDoHAndSNI.connectAfterResolvingViaDoH(domainName, 443, subresource, customUserAgent, true); // Using IPv6 by default, if available.
    }

    public static HttpsURLConnection connectAfterResolvingViaDoH(String domainName, String subresource, boolean preferIPv6IfAvailable) throws IOException {
        return HttpsConnectionWithDoHAndSNI.connectAfterResolvingViaDoH(domainName, 443, subresource, null, preferIPv6IfAvailable);
    }

    public static HttpsURLConnection connectAfterResolvingViaDoH(String domainName, String subresource, String customUserAgent, boolean preferIPv6IfAvailable) throws IOException {
        return HttpsConnectionWithDoHAndSNI.connectAfterResolvingViaDoH(domainName, 443, subresource, customUserAgent, preferIPv6IfAvailable);
    }

    public static HttpsURLConnection connectAfterResolvingViaDoH(String domainName, int port, String subresource) throws IOException {
        return HttpsConnectionWithDoHAndSNI.connectAfterResolvingViaDoH(domainName, port, subresource, null, true); // Using IPv6 by default, if available.
    }

    public static HttpsURLConnection connectAfterResolvingViaDoH(String domainName, int port, String subresource, String customUserAgent) throws IOException {
        return HttpsConnectionWithDoHAndSNI.connectAfterResolvingViaDoH(domainName, port, subresource, customUserAgent, true); // Using IPv6 by default, if available.
    }

    public static HttpsURLConnection connectAfterResolvingViaDoH(String domainName, int port, String subresource, String customUserAgent, boolean preferIPv6IfAvailable) throws IOException {
        DNSOverHTTPSResolver client = (customUserAgent == null || "".equals(customUserAgent)) ?  new DNSOverHTTPSResolver() : new DNSOverHTTPSResolver(customUserAgent);

        if(preferIPv6IfAvailable) {
            List<String> results = client.resolveToIPv6(domainName);

            if(results.isEmpty()) {
                return HttpsConnectionWithDoHAndSNI.connectAfterResolvingViaDoH(domainName, port, subresource, customUserAgent, false);
            }
            else {
                return HttpsConnectionWithDoHAndSNI.openConnection(results.get(0), domainName, port, subresource);
            }
        }
        else {
            List<String> results = client.resolveToIPv4(domainName);

            if(results.isEmpty()) {
                throw new IOException("No DNS resolution was possible for the domain name " + domainName + " .");
            }
            else {
                return HttpsConnectionWithDoHAndSNI.openConnection(results.get(0), domainName, port, subresource);
            }
        }
    }

    private static HttpsURLConnection openConnection(String ip, String domainName, int port, String subresource) throws IOException {
        try {
            if(ip.contains(":")) {
                ip = "[" + ip + "]";
            }
    
            HttpsURLConnection.setDefaultSSLSocketFactory(TLSSocketFactoryWithDoHAndSNI.getInstance(domainName));

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
