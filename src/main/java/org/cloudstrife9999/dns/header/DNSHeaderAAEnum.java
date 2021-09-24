package org.cloudstrife9999.dns.header;

import java.util.stream.Stream;

public enum DNSHeaderAAEnum {
    NOT_AUTHORITY(0), AUTHORITY(1);

    private int code;

    private DNSHeaderAAEnum(int code) {
        this.code = code;
    }

    public int getCode() {
        return this.code;
    }

    public int getMaskedCode() {
        return (this.code << 2) & 0x04;
    }

    public static DNSHeaderAAEnum fromCode(int code) {
        return Stream.of(DNSHeaderAAEnum.values()).filter(elm -> elm.getCode() == code).toList().get(0);
    }
}
