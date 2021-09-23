package org.cloudstrife9999.dns.header;

public enum DNSHeaderRDEnum {
    RECURSION_NOT_DESIRED(0), RECURSION_DESIRED(1);

    private int code;

    private DNSHeaderRDEnum(int code) {
        this.code = code;
    }

    public int getCode() {
        return this.code;
    }

    public int getMaskedCode() {
        return this.code & 0x01;
    }
}
