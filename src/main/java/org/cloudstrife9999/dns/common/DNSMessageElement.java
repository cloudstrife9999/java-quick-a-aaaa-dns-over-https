package org.cloudstrife9999.dns.common;

public interface DNSMessageElement {
    public abstract void unpack();

    public abstract void updateBinaryRepresentation();

    public abstract byte[] getBytes();
}
