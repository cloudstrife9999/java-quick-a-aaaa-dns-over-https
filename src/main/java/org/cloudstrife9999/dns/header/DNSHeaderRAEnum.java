package org.cloudstrife9999.dns.header;

public enum DNSHeaderRAEnum {
    RECURSION_NOT_AVAILABLE(0), RECURSION_AVAILABLE(1);

    private int code;

    private DNSHeaderRAEnum(int code) {
        this.code = code;
    }

    public int getCode() {
        return this.code;
    }

    public int getMaskedCode() {
        return (this.code << 7) & 0x80;
    }
}
