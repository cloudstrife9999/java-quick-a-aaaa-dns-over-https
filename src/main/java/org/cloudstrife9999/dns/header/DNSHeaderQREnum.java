package org.cloudstrife9999.dns.header;

import java.util.stream.Stream;

public enum DNSHeaderQREnum {
    QUERY(0), RESPONSE(1);

    private int code;

    private DNSHeaderQREnum(int code) {
        this.code = code;
    }

    public int getCode() {
        return this.code;
    }

    public int getMaskedCode() {
        return (this.code << 7) & 0x80;
    }

    public static DNSHeaderQREnum fromCode(int code) {
        return Stream.of(DNSHeaderQREnum.values()).filter(elm -> elm.getCode() == code).toList().get(0);
    }
}
