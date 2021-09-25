package org.cloudstrife9999.dns.record;

import java.util.stream.Stream;

import org.cloudstrife9999.dns.Utils;

public enum DNSRRClassEnum {
    IN(1),
    CS(2),
    CH(3),
    HS(4);

    private int code;

    private DNSRRClassEnum(int code) {
        this.code = code;
    }

    public int getCode() {
        return this.code;
    }

    public byte[] getCodeBytes() {
        return Utils.unsignedIntToTwoBytes(this.code);
    }

    public static DNSRRClassEnum fromCode(int code) {
        return Stream.of(DNSRRClassEnum.values()).filter(elm -> elm.getCode() == code).toList().get(0);
    }
}
