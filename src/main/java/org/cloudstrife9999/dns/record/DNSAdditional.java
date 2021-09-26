package org.cloudstrife9999.dns.record;

import org.cloudstrife9999.dns.common.DNSResourceRecord;

public class DNSAdditional extends DNSResourceRecord {

    public DNSAdditional() {}

    public DNSAdditional(byte[] bytes) {
        this.binaryRepresentation = bytes;
        this.unpack();
    }

    public DNSAdditional(byte[] bytes, int offset, boolean hasDomainName) {
        this.binaryRepresentation = bytes;
        this.offset = offset;
        this.hasDomainName = hasDomainName;
        this.unpack();
    }
}
