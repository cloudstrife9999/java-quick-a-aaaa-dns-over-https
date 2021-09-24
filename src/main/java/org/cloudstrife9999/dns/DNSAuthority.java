package org.cloudstrife9999.dns;

public class DNSAuthority extends DNSResourceRecord {

    public DNSAuthority() {}

    public DNSAuthority(byte[] bytes) {
        this.binaryRepresentation = bytes;
        this.unpack();
    }

    public DNSAuthority(byte[] bytes, int offset, boolean hasDomainName) {
        this.binaryRepresentation = bytes;
        this.offset = offset;
        this.hasDomainName = hasDomainName;
        this.unpack();
    }
}
