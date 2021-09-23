package org.cloudstrife9999.dns.question;

public enum DNSQuestionQClassEnum {
    IN((short) 1),
    CS((short) 2),
    CH((short) 3),
    HS((short) 4),
    STAR((short) 255); // ANY class (*).

    private short code;

    private DNSQuestionQClassEnum(short code) {
        this.code = code;
    }

    public short getCode() {
        return this.code;
    }

    public byte[] getCodeBytes() {
        return new byte[]{(byte)((this.code >> 8) & 0xFF), (byte)(this.code & 0xFF)};
    }
}
