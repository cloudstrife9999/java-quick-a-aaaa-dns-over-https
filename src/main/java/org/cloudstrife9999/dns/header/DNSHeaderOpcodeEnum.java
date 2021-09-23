package org.cloudstrife9999.dns.header;

public enum DNSHeaderOpcodeEnum {
    QUERY(0),
    IQUERY(1),
    STATUS(2),
    RESERVED_3(3),
    RESERVED_4(4),
    RESERVED_5(5),
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

    private DNSHeaderOpcodeEnum(int code) {
        this.code = code;
    }

    public int getCode() {
        return this.code;
    }

    public int getMaskedCode() {
        return (this.code << 3) & 0x78;
    }
}
