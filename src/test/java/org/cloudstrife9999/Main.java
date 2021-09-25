package org.cloudstrife9999;

import java.io.IOException;

import javax.net.ssl.HttpsURLConnection;

import org.cloudstrife9999.connection.HttpsConnectionWithDoH;

public class Main {
    public static void main(String[] args) {
        try {
            HttpsURLConnection connection = HttpsConnectionWithDoH.connectAfterResolvingViaDoH("www.google.com", "maps", false);

            connection.setDoOutput(true);
            connection.setRequestMethod("GET");
            connection.setRequestProperty("User-Agent", "Java Client");

            byte[] result = new byte[connection.getInputStream().available()];
            connection.getInputStream().read(result);

            System.out.println(new String(result));
        }
        catch(IOException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
