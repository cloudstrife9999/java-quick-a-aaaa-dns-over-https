package org.cloudstrife9999;

import java.io.IOException;
import java.util.List;

import org.cloudstrife9999.dns.Doh;

public class Main {
    public static void main(String[] args) {
        try {
            Doh resolver = new Doh();
            List<String> responseIPv4 = resolver.resIPv4("www.google.com");
            List<String> responseIPv6 = resolver.resIPv6("www.google.com");
            
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
