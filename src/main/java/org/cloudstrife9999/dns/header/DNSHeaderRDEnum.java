package org.cloudstrife9999.dns.header;

import java.util.stream.Stream;

public enum DNSHeaderRDEnum {
    RECURSION_NOT_DESIRED(0), RECURSION_DESIRED(1);

    private int code;

    private DNSHeaderRDEnum(int code) {
        this.code = code;
    }

    public int getCode() {
        return this.code;
    }

    public int getMaskedCode() {
        return this.code & 0x01;
    }

    public static DNSHeaderRDEnum fromCode(int code) {
        return Stream.of(DNSHeaderRDEnum.values()).filter(elm -> elm.getCode() == code).toList().get(0);
    }
}
