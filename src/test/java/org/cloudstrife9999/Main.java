package org.cloudstrife9999;

import java.io.IOException;

public class Main {
    public static void main(String[] args) {
        try {
            Doh resolver = new Doh();
            String[] responseIPv4 = resolver.resolveIPv4("www.google.com");
            String[] responseIPv6 = resolver.resolveIPv6("www.google.com");
            
            for(String elm : responseIPv4) {
                System.out.println(elm);
            }

            for(String elm : responseIPv6) {
                System.out.println(elm);
            }
        }
        catch(IOException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
