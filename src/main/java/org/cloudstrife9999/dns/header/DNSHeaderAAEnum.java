package org.cloudstrife9999.dns.header;

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
}
