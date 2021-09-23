package org.cloudstrife9999.dns;

import java.nio.ByteBuffer;

import org.cloudstrife9999.dns.question.DNSQuestionQClassEnum;
import org.cloudstrife9999.dns.question.DNSQuestionQTypeEnum;

public class DNSQuestion implements DNSMessageElement {
    private byte[] binaryRepresentation;
    private String qName;
    private DNSQuestionQTypeEnum qType;
    private DNSQuestionQClassEnum qClass;

    public DNSQuestion() {}

    public DNSQuestion(byte[] bytes) {
        this.binaryRepresentation = bytes;
        this.validateBinaryRepresentation();
    }
    
    @Override
    public void updateBinaryRepresentation() {
        byte[] qNameBytes = this.generateQnameRepresentation();

        ByteBuffer buffer = ByteBuffer.allocate(qNameBytes.length + 2);

        buffer.put(qNameBytes);
        buffer.put(this.qType.getCodeBytes());
        buffer.put(this.qClass.getCodeBytes());

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
            throw new IllegalStateException("Null DNS message question field.");
        }
    }

    private byte[] generateQnameRepresentation() {
        ByteBuffer buffer = ByteBuffer.allocate(this.qName.length() + 2);

        for(String token: this.qName.split("\\.")) {
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