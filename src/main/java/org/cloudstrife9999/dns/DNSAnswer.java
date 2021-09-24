package org.cloudstrife9999.dns;

public class DNSAnswer extends DNSResourceRecord {

    public DNSAnswer() {}

    public DNSAnswer(byte[] bytes) {
        this.binaryRepresentation = bytes;
        this.unpack();
    }

    public DNSAnswer(byte[] bytes, int offset, boolean hasDomainName) {
        this.binaryRepresentation = bytes;
        this.offset = offset;
        this.hasDomainName = hasDomainName;
        this.unpack();
    }
}
