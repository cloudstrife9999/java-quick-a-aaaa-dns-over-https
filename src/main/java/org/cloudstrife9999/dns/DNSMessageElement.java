package org.cloudstrife9999.dns;

public interface DNSMessageElement {
    public abstract void unpack();

    public abstract void updateBinaryRepresentation();

    public abstract byte[] getBytes();
}
