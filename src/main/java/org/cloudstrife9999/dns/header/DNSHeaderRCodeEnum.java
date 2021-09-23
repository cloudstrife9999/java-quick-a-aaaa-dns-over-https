package org.cloudstrife9999.dns.header;

public enum DNSHeaderRCodeEnum {
    NO_ERROR(0),
    FORMAT_ERROR(1),
    SERVER_FAILURE(2),
    NAME_ERROR(3),
    NOT_IMPLEMENTED(4),
    REFUSED(5),
    RESERVED_6(6),
    RESERVED_7(7),
    RESERVED_8(8),
    RESERVED_9(9),
    RESERVED_10(10),
    RESERVED_11(11),
    RESERVED_12(12),
    RESERVED_13(13),
    RESERVED_14(14),
    RESERVED_15(15);

    private int code;

    private DNSHeaderRCodeEnum(int code) {
        this.code = code;
    }

    public int getCode() {
        return this.code;
    }

    public int getMaskedCode() {
        return this.code & 0x0F;
    }
}
