package org.cloudstrife9999.dns.question;

public enum DNSQuestionQTypeEnum {
    A((short) 1),
    NS((short) 2),
    MD((short) 3),
    MF((short) 4),
    CNAME((short) 5),
    SOA((short) 6),
    MB((short) 7),
    MG((short) 8),
    MR((short) 9),
    NULL((short) 10),
    WKS((short) 11),
    PTR((short) 12),
    HINFO((short) 13),
    MINFO((short) 14),
    MX((short) 15),
    TXT((short) 16),
    AAAA((short) 28),
    AXFR((short) 252),
    MAILB((short) 253),
    MAILA((short) 254),
    STAR((short) 255); // ALL records (*).

    private short code;

    private DNSQuestionQTypeEnum(short code) {
        this.code = code;
    }

    public short getCode() {
        return this.code;
    }

    public byte[] getCodeBytes() {
        return new byte[]{(byte)((this.code >> 8) & 0xFF), (byte)(this.code & 0xFF)};
    }
}
