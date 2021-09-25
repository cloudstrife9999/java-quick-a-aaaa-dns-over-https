package org.cloudstrife9999.dns.header;

public class DNSHeaderFlags {
    private byte[] representation;
    private DNSHeaderQREnum qr;
    private DNSHeaderOpcodeEnum opcode;
    private DNSHeaderAAEnum aa;
    private DNSHeaderTCEnum tc;
    private DNSHeaderRDEnum rd;
    private DNSHeaderRAEnum ra;
    private static final int Z = 0;
    private DNSHeaderRCodeEnum rCode;

    public DNSHeaderFlags(DNSHeaderQREnum qr, DNSHeaderOpcodeEnum opcode, DNSHeaderAAEnum aa, DNSHeaderTCEnum tc, DNSHeaderRDEnum rd, DNSHeaderRAEnum ra, DNSHeaderRCodeEnum rCode) {
        this.qr = qr;
        this.opcode = opcode;
        this.aa = aa;
        this.tc = tc;
        this.rd = rd;
        this.ra = ra;
        this.rCode = rCode;
        this.representation = this.pack();
    }

    public DNSHeaderFlags(byte[] representation) {
        this.representation = representation;

        this.unpack();
    }

    public byte[] getFlagsBytes() {
        return this.representation;
    }

    public DNSHeaderQREnum getQr() {
        return this.qr;
    }

    public DNSHeaderOpcodeEnum getOpcode() {
        return this.opcode;
    }

    public DNSHeaderAAEnum getAa() {
        return this.aa;
    }

    public DNSHeaderTCEnum getTc() {
        return this.tc;
    }

    public DNSHeaderRDEnum getRd() {
        return this.rd;
    }

    public DNSHeaderRAEnum getRa() {
        return this.ra;
    }

    public static int getZ() {
        return DNSHeaderFlags.Z;
    }

    public DNSHeaderRCodeEnum getrCode() {
        return this.rCode;
    }

    private byte[] pack() {
        byte[] flags = new byte[2];

        flags[0] = (byte)((this.qr.getMaskedCode() + this.opcode.getMaskedCode() + this.aa.getMaskedCode() + this.tc.getMaskedCode() + this.rd.getMaskedCode()) & 0xFF);
        flags[1] = (byte)((this.ra.getMaskedCode() + ((DNSHeaderFlags.Z << 4) & 0x70) + this.rCode.getMaskedCode()) & 0xFF);

        return flags;
    }

    private void unpack() {
        this.qr = DNSHeaderQREnum.fromCode((this.representation[0] >> 7) & 0x01);
        this.opcode = DNSHeaderOpcodeEnum.fromCode(((this.representation[0] << 1) >> 4) & 0x0F);
        this.aa = DNSHeaderAAEnum.fromCode(((this.representation[0] << 5) >> 7) & 0x01);
        this.tc = DNSHeaderTCEnum.fromCode(((this.representation[0] << 6) >> 7) & 0x01);
        this.rd = DNSHeaderRDEnum.fromCode(((this.representation[0] << 7) >> 7) & 0x01);
        this.ra = DNSHeaderRAEnum.fromCode((this.representation[1] >> 7) & 0x01);
        this.rCode = DNSHeaderRCodeEnum.fromCode(((this.representation[1] << 4) >> 4) & 0x0F);
    }
}
