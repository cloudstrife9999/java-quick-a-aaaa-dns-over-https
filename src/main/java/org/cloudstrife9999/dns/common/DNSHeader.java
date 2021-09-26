package org.cloudstrife9999.dns.common;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

import org.cloudstrife9999.dns.header.DNSHeaderAAEnum;
import org.cloudstrife9999.dns.header.DNSHeaderFlags;
import org.cloudstrife9999.dns.header.DNSHeaderOpcodeEnum;
import org.cloudstrife9999.dns.header.DNSHeaderQREnum;
import org.cloudstrife9999.dns.header.DNSHeaderRAEnum;
import org.cloudstrife9999.dns.header.DNSHeaderRCodeEnum;
import org.cloudstrife9999.dns.header.DNSHeaderRDEnum;
import org.cloudstrife9999.dns.header.DNSHeaderTCEnum;

public class DNSHeader implements DNSMessageElement {
    public static final int HEADER_LENGTH = 12;
    private byte[] binaryRepresentation; // 12 bytes.
    private byte[] transactionID; // 2 bytes; must be unpredictable.
    private DNSHeaderFlags headerFlags; // 2 bytes.
    private int qdCount; // 2 bytes; unsigned.
    private int anCount; // 2 bytes; unsigned.
    private int nsCount; // 2 bytes; unsigned.
    private int arCount; // 2 bytes; unsigned.

    public DNSHeader(DNSHeaderFlags flags, int qdCount, int anCount, int nsCount, int arCount) {
        this.headerFlags = flags;
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
        DNSHeaderFlags flags = new DNSHeaderFlags(
            DNSHeaderQREnum.QUERY,
            DNSHeaderOpcodeEnum.QUERY,
            DNSHeaderAAEnum.NOT_AUTHORITY,
            DNSHeaderTCEnum.NOT_TRUNCATED,
            DNSHeaderRDEnum.RECURSION_DESIRED,
            DNSHeaderRAEnum.RECURSION_NOT_AVAILABLE,
            DNSHeaderRCodeEnum.NO_ERROR
        );

        return new DNSHeader(flags, 1, 0, 0, 0);
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
        this.headerFlags = new DNSHeaderFlags(flags);

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

        byte[] flags = this.headerFlags.getFlagsBytes();
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
}
