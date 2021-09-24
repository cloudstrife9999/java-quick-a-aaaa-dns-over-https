package org.cloudstrife9999.dns.question;

import java.util.stream.Stream;

import org.cloudstrife9999.dns.Utils;

public enum DNSQuestionQClassEnum {
    IN(1),
    CS(2),
    CH(3),
    HS(4),
    STAR(255); // ANY class (*).

    private int code;

    private DNSQuestionQClassEnum(int code) {
        this.code = code;
    }

    public int getCode() {
        return this.code;
    }

    public byte[] getCodeBytes() {
        return Utils.unsignedIntToTwoBytes(this.code);
    }

    public static DNSQuestionQClassEnum fromCode(int code) {
        return Stream.of(DNSQuestionQClassEnum.values()).filter(elm -> elm.getCode() == code).toList().get(0);
    }
}
