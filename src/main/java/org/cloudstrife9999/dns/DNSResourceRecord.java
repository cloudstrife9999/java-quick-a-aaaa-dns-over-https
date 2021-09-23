package org.cloudstrife9999.dns;

import java.nio.ByteBuffer;

import org.cloudstrife9999.dns.question.DNSQuestionQClassEnum;
import org.cloudstrife9999.dns.question.DNSQuestionQTypeEnum;

public abstract class DNSResourceRecord implements DNSMessageElement {
    protected byte[] binaryRepresentation;
    protected String domainName;
    protected DNSQuestionQTypeEnum rDataType; // This should be a different enum.
    protected DNSQuestionQClassEnum rDataClass; // This should be a different enum.
    protected int ttl;
    protected short rdLength;
    protected byte[] rData;

    @Override
    public void updateBinaryRepresentation() {
        byte[] domainNameRepresentation = this.generateNameRepresentation();
        byte[] typeBytes = this.rDataType.getCodeBytes();
        byte[] classBytes = this.rDataClass.getCodeBytes();
        byte[] ttlBytes = ByteBuffer.allocate(4).putInt(this.ttl).array();
        byte[] rdLengthBytes = new byte[]{(byte)((domainNameRepresentation.length >> 8) & 0xFF), (byte)(domainNameRepresentation.length & 0xFF)};
        this.rData = this.generateRData();

        ByteBuffer buffer = ByteBuffer.allocate(domainNameRepresentation.length + typeBytes.length + classBytes.length + ttlBytes.length + rdLengthBytes.length + this.rData.length);

        buffer.put(domainNameRepresentation);
        buffer.put(typeBytes);
        buffer.put(classBytes);
        buffer.put(ttlBytes);
        buffer.put(rdLengthBytes);
        buffer.put(this.rData);

        this.binaryRepresentation = buffer.array();
    }

    protected abstract byte[] generateRData();

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
            throw new IllegalStateException("Null DNS message question field.");
        }
    }

    private byte[] generateNameRepresentation() {
        ByteBuffer buffer = ByteBuffer.allocate(this.domainName.length() + 2);

        for(String token: this.domainName.split("\\.")) {
            buffer.put(this.getTokenWithLengthPrefix(token));
        }

        buffer.put((byte) 0x00);

        return buffer.array();
    }

    private byte[] getTokenWithLengthPrefix(String token) {
        byte length = (byte) (token.length() & 0xFF);

        ByteBuffer buffer = ByteBuffer.allocate(token.getBytes().length + 1);
        buffer.put(length);
        buffer.put(token.getBytes());

        return buffer.array();
    }
}
