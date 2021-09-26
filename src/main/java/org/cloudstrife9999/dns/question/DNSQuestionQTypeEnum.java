package org.cloudstrife9999.dns.question;

import java.util.stream.Stream;

import org.cloudstrife9999.dns.common.Utils;

public enum DNSQuestionQTypeEnum {
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
    AAAA(28),
    AXFR(252),
    MAILB(253),
    MAILA(254),
    STAR(255); // ALL records (*).

    private int code;

    private DNSQuestionQTypeEnum(int code) {
        this.code = code;
    }

    public int getCode() {
        return this.code;
    }

    public byte[] getCodeBytes() {
        return Utils.unsignedIntToTwoBytes(this.code);
    }

    public static DNSQuestionQTypeEnum fromCode(int code) {
        return Stream.of(DNSQuestionQTypeEnum.values()).filter(elm -> elm.getCode() == code).toList().get(0);
    }

    public boolean refersToAnAQuery() {
        return DNSQuestionQTypeEnum.A.equals(this);
    }

    public boolean refersToAnAAAAQuery() {
        return DNSQuestionQTypeEnum.AAAA.equals(this);
    }
}
