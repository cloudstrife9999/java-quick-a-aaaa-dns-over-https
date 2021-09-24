package org.cloudstrife9999.dns;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

import org.cloudstrife9999.dns.header.DNSHeaderAAEnum;
import org.cloudstrife9999.dns.header.DNSHeaderOpcodeEnum;
import org.cloudstrife9999.dns.header.DNSHeaderQREnum;
import org.cloudstrife9999.dns.header.DNSHeaderRAEnum;
import org.cloudstrife9999.dns.header.DNSHeaderRCodeEnum;
import org.cloudstrife9999.dns.header.DNSHeaderRDEnum;
import org.cloudstrife9999.dns.header.DNSHeaderTCEnum;

public class DNSHeader implements DNSMessageElement {
    public static final int HEADER_LENGTH = 12;
    private byte[] binaryRepresentation;
    private byte[] transactionID; // 2 bytes; must be unpredictable.
    private DNSHeaderQREnum qr;
    private DNSHeaderOpcodeEnum opcode;
    private DNSHeaderAAEnum aa;
    private DNSHeaderTCEnum tc;
    private DNSHeaderRDEnum rd;
    private DNSHeaderRAEnum ra;
    private static final int Z = 0;
    private DNSHeaderRCodeEnum rCode;
    private int qdCount;
    private int anCount;
    private int nsCount;
    private int arCount;

    public DNSHeader(DNSHeaderQREnum qr, DNSHeaderOpcodeEnum opcode, DNSHeaderAAEnum aa, DNSHeaderTCEnum tc, DNSHeaderRDEnum rd, DNSHeaderRAEnum ra, DNSHeaderRCodeEnum rCode, short qdCount, short anCount, short nsCount, short arCount) {
        this.qr = qr;
        this.opcode = opcode;
        this.aa = aa;
        this.tc = tc;
        this.rd = rd;
        this.ra = ra;
        this.rCode = rCode;
        this.qdCount = qdCount;
        this.anCount = anCount;
        this.nsCount = nsCount;
        this.arCount = arCount;
    }

    public DNSHeader(byte[] bytes) {
        this.binaryRepresentation = bytes;
        this.unpack();
    }

    public static DNSHeader quickHeaderForQuery() {
        return new DNSHeader(
            DNSHeaderQREnum.QUERY,
            DNSHeaderOpcodeEnum.QUERY,
            DNSHeaderAAEnum.NOT_AUTHORITY,
            DNSHeaderTCEnum.NOT_TRUNCATED, // TODO: this is to be determined.
            DNSHeaderRDEnum.RECURSION_DESIRED,
            DNSHeaderRAEnum.RECURSION_NOT_AVAILABLE,
            DNSHeaderRCodeEnum.NO_ERROR,
            (short) 1, (short) 0, (short) 0, (short) 0
        );
    }

    public byte[] getTransactionID() {
        if(this.transactionID == null) {
            return new byte[]{};
        }
        else {
            return this.transactionID;
        }
    }

    public int getQdCount() {
        return this.qdCount;
    }

    public int getAnCount() {
        return this.anCount;
    }

    public int getNsCount() {
        return this.nsCount;
    }

    public int getArCount() {
        return this.arCount;
    }

    @Override
    public void unpack() {
        assert this.binaryRepresentation.length == DNSHeader.HEADER_LENGTH;

        int counter = 0;

        this.transactionID = Arrays.copyOfRange(this.binaryRepresentation, counter, counter + 2);
        counter += 2;

        byte[] flags = Arrays.copyOfRange(this.binaryRepresentation, counter, counter + 2);
        counter +=2;
        this.unpackFlags(flags);

        this.qdCount = Utils.twoBytesToUnsignedInt(Arrays.copyOfRange(this.binaryRepresentation, counter, counter + 2));
        counter += 2;

        this.anCount = Utils.twoBytesToUnsignedInt(Arrays.copyOfRange(this.binaryRepresentation, counter, counter + 2));
        counter += 2;

        this.nsCount = Utils.twoBytesToUnsignedInt(Arrays.copyOfRange(this.binaryRepresentation, counter, counter + 2));
        counter += 2;

        this.arCount = Utils.twoBytesToUnsignedInt(Arrays.copyOfRange(this.binaryRepresentation, counter, counter + 2));
        counter += 2;

        assert counter == this.binaryRepresentation.length;
    }

    @Override
    public void updateBinaryRepresentation() {
        this.transactionID = this.generateFreshTransactionID();

        byte[] flags = this.getFlagsBytes();
        byte[] qdCountBytes = new byte[]{(byte)((this.qdCount >> 8) & 0xFF), (byte)(this.qdCount & 0xFF)};
        byte[] anCountBytes = new byte[]{(byte)((this.anCount >> 8) & 0xFF), (byte)(this.anCount & 0xFF)};
        byte[] nsCountBytes = new byte[]{(byte)((this.nsCount >> 8) & 0xFF), (byte)(this.nsCount & 0xFF)};
        byte[] arCountBytes = new byte[]{(byte)((this.arCount >> 8) & 0xFF), (byte)(this.arCount & 0xFF)};

        ByteBuffer buffer = ByteBuffer.allocate(this.transactionID.length + flags.length + qdCountBytes.length + anCountBytes.length + nsCountBytes.length + arCountBytes.length);

        buffer.put(this.transactionID);
        buffer.put(flags);
        buffer.put(qdCountBytes);
        buffer.put(anCountBytes);
        buffer.put(nsCountBytes);
        buffer.put(arCountBytes);

        this.binaryRepresentation = buffer.array();
    }

    @Override
    public byte[] getBytes() {
        if (this.binaryRepresentation == null){
            this.updateBinaryRepresentation();
        }
        
        if (this.binaryRepresentation != null) {
            return this.binaryRepresentation;
        }
        else {
            throw new IllegalStateException("Null DNS message header field.");
        }
    }

    private byte[] generateFreshTransactionID() {
        SecureRandom random = new SecureRandom();

        byte[] newTransactionID = new byte[2];

        random.nextBytes(newTransactionID);

        return newTransactionID;
    }

    private byte[] getFlagsBytes() {
        byte[] flags = new byte[2];

        flags[0] = (byte)((this.qr.getMaskedCode() + this.opcode.getMaskedCode() + this.aa.getMaskedCode() + this.tc.getMaskedCode() + this.rd.getMaskedCode()) & 0xFF);
        flags[1] = (byte)((this.ra.getMaskedCode() + ((DNSHeader.Z << 4) & 0x70) + this.rCode.getMaskedCode()) & 0xFF);

        return flags;
    }

    private void unpackFlags(byte[] flags) {
        this.qr = DNSHeaderQREnum.fromCode((flags[0] >> 7) & 0x01);
        this.opcode = DNSHeaderOpcodeEnum.fromCode(((flags[0] << 1) >> 4) & 0x0F);
        this.aa = DNSHeaderAAEnum.fromCode(((flags[0] << 5) >> 7) & 0x01);
        this.tc = DNSHeaderTCEnum.fromCode(((flags[0] << 6) >> 7) & 0x01);
        this.rd = DNSHeaderRDEnum.fromCode(((flags[0] << 7) >> 7) & 0x01);
        this.ra = DNSHeaderRAEnum.fromCode((flags[1] >> 7) & 0x01);
        this.rCode = DNSHeaderRCodeEnum.fromCode(((flags[1] << 4) >> 4) & 0x0F);
    }
}
