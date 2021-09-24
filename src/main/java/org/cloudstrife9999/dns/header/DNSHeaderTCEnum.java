package org.cloudstrife9999.dns.header;

import java.util.stream.Stream;

public enum DNSHeaderTCEnum {
    NOT_TRUNCATED(0), TRUNCATED(1);

    private int code;

    private DNSHeaderTCEnum(int code) {
        this.code = code;
    }

    public int getCode() {
        return this.code;
    }

    public int getMaskedCode() {
        return (this.code << 1) & 0x02;
    }

    public static DNSHeaderTCEnum fromCode(int code) {
        return Stream.of(DNSHeaderTCEnum.values()).filter(elm -> elm.getCode() == code).toList().get(0);
    }
}
