package org.cloudstrife9999.dns;

public class DNSAuthority extends DNSResourceRecord {
    public DNSAuthority() {}

    public DNSAuthority(byte[] bytes) {
        this.binaryRepresentation = bytes;
        this.validateBinaryRepresentation();
    }

    @Override
    protected byte[] generateRData() {
        return new byte[]{}; //TODO
    }

    @Override
    public void validateBinaryRepresentation() {
        // TODO Auto-generated method stub
        
    }
}
