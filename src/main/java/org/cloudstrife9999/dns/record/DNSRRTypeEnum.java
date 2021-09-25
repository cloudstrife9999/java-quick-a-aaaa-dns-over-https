package org.cloudstrife9999.dns.record;

import java.util.stream.Stream;

import org.cloudstrife9999.dns.Utils;

public enum DNSRRTypeEnum {
    A(1),
    NS(2),
    MD(3),
    MF(4),
    CNAME(5),
    SOA(6),
    MB(7),
    MG(8),
    MR(9),
    NULL(10),
    WKS(11),
    PTR(12),
    HINFO(13),
    MINFO(14),
    MX(15),
    TXT(16),
    AAAA(28);

    private int code;

    private DNSRRTypeEnum(int code) {
        this.code = code;
    }

    public int getCode() {
        return this.code;
    }

    public byte[] getCodeBytes() {
        return Utils.unsignedIntToTwoBytes(this.code);
    }

    public static DNSRRTypeEnum fromCode(int code) {
        return Stream.of(DNSRRTypeEnum.values()).filter(elm -> elm.getCode() == code).toList().get(0);
    }

    public boolean refersToAnAResponse() {
        return DNSRRTypeEnum.A.equals(this);
    }

    public boolean refersToAnAAAAResponse() {
        return DNSRRTypeEnum.AAAA.equals(this);
    }
}
