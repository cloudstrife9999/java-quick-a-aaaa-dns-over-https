package org.cloudstrife9999.dns;

public class DNSAnswer extends DNSResourceRecord {

    public DNSAnswer() {}

    public DNSAnswer(byte[] bytes) {
        this.binaryRepresentation = bytes;
        this.validateBinaryRepresentation();
    }

    @Override
    protected byte[] generateRData() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void validateBinaryRepresentation() {
        // TODO Auto-generated method stub
        
    }
}
