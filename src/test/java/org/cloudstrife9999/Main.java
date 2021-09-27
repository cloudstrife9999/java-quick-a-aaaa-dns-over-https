package org.cloudstrife9999;

import java.io.IOException;

import javax.net.ssl.HttpsURLConnection;

import org.cloudstrife9999.connection.HttpsConnectionWithDoHAndSNI;

public class Main {
    public static void main(String[] args) {
        try {
            String customUserAgent = "My Custom User-Agent";

            HttpsURLConnection connection = HttpsConnectionWithDoHAndSNI.connectAfterResolvingViaDoH("www.google.com", "maps", customUserAgent, false);

            connection.setDoOutput(true);
            connection.setRequestMethod("GET");
            connection.setRequestProperty("User-Agent", customUserAgent);

            byte[] result = new byte[connection.getInputStream().available()];
            connection.getInputStream().read(result);

            System.out.println(new String(result));
        }
        catch(IOException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
