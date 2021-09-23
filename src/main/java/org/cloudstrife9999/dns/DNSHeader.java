package org.cloudstrife9999.dns;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

import org.cloudstrife9999.dns.header.DNSHeaderAAEnum;
import org.cloudstrife9999.dns.header.DNSHeaderOpcodeEnum;
import org.cloudstrife9999.dns.header.DNSHeaderQREnum;
import org.cloudstrife9999.dns.header.DNSHeaderRAEnum;
import org.cloudstrife9999.dns.header.DNSHeaderRCodeEnum;
import org.cloudstrife9999.dns.header.DNSHeaderRDEnum;
import org.cloudstrife9999.dns.header.DNSHeaderTCEnum;

public class DNSHeader implements DNSMessageElement {
    private static final int HEADER_LENGTH = 12;
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
    private short qdCount;
    private short anCount;
    private short nsCount;
    private short arCount;

    public DNSHeader() {}

    public DNSHeader(byte[] bytes) {
        this.binaryRepresentation = bytes;
        this.validateBinaryRepresentation();
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
    public void validateBinaryRepresentation() {
        // TODO Auto-generated method stub
        
    }

    @Override
    public byte[] getBytes() {
        if (this.binaryRepresentation == null){
            this.updateBinaryRepresentation();
            this.validateBinaryRepresentation();
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
}
