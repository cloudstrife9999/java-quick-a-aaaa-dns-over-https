package org.cloudstrife9999.dns;

public interface DNSMessageElement {
    public abstract void updateBinaryRepresentation();

    public abstract void validateBinaryRepresentation();

    public abstract byte[] getBytes();
}
