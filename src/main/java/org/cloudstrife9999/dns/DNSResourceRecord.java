package org.cloudstrife9999.dns;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.cloudstrife9999.dns.question.DNSQuestionQClassEnum;
import org.cloudstrife9999.dns.question.DNSQuestionQTypeEnum;

public abstract class DNSResourceRecord implements DNSMessageElement {
    protected byte[] binaryRepresentation;
    protected String domainName = null;
    protected int offset = -1;
    protected boolean hasDomainName;
    protected DNSQuestionQTypeEnum rDataType; // This should be a different enum.
    protected DNSQuestionQClassEnum rDataClass; // This should be a different enum.
    protected int ttl; // Must be treated as an unsigned 32-bit integer.
    protected int rdLength;
    protected byte[] rData;

    public String getDomainName() {
        return this.domainName;
    }

    public void setDomainName(String domainName) {
        this.domainName = domainName;
    }

    public int getOffset() {
        return offset;
    }

    public DNSQuestionQTypeEnum getrDataType() {
        return this.rDataType;
    }

    public DNSQuestionQClassEnum getrDataClass() {
        return this.rDataClass;
    }

    public int getRdLength() {
        return this.rdLength;
    }

    public int getTtl() {
        return this.ttl;
    }

    public byte[] getrData() {
        return this.rData;
    }

    public String getRDataAsString() {
        return new String(this.rData);
    }

    public String getRDataAsIPv4() throws IOException {
        Inet4Address address = (Inet4Address) InetAddress.getByAddress(this.rData);

        return address.getHostAddress();
    }

    public String getRDataAsIPv6() throws IOException {
        Inet6Address address = (Inet6Address) InetAddress.getByAddress(this.rData);

        return address.getHostAddress();
    }

    public static byte[] getEmptyRecord() {
        return new byte[]{};
    }

    @Override
    public void unpack() {
        if(this.offset == -1) {
            this.unpackWithNullCharacter();
        }
        else if(this.hasDomainName){
            this.unpackWithOffsetAndDomainName();
        }
        else {
            this.unpackWithOffset();
        }
    }

    @Override
    public void updateBinaryRepresentation() {
        byte[] domainNameRepresentation = this.generateNameRepresentation();
        byte[] typeBytes = this.rDataType.getCodeBytes();
        byte[] classBytes = this.rDataClass.getCodeBytes();
        byte[] ttlBytes = ByteBuffer.allocate(4).putInt(this.ttl).array();
        byte[] rdLengthBytes = new byte[]{(byte)((domainNameRepresentation.length >> 8) & 0xFF), (byte)(domainNameRepresentation.length & 0xFF)};

        ByteBuffer buffer = ByteBuffer.allocate(domainNameRepresentation.length + typeBytes.length + classBytes.length + ttlBytes.length + rdLengthBytes.length + this.rData.length);

        buffer.put(domainNameRepresentation);
        buffer.put(typeBytes);
        buffer.put(classBytes);
        buffer.put(ttlBytes);
        buffer.put(rdLengthBytes);
        buffer.put(this.rData);

        this.binaryRepresentation = buffer.array();
    }

    @Override
    public byte[] getBytes() {
        if (this.binaryRepresentation == null){
            this.updateBinaryRepresentation();
        }
        
        if (this.binaryRepresentation != null) {
            return this.binaryRepresentation;
        }
        else {
            throw new IllegalStateException("Null DNS message question field.");
        }
    }

    private byte[] generateNameRepresentation() {
        if (this.domainName == null) {
            return new byte[]{};
        }

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

    private void unpackWithNullCharacter() {
        int counter = 0;

        while(this.binaryRepresentation[counter] != 0x00) {
            counter++;
        }

        assert this.binaryRepresentation[counter] == 0x00;

        this.domainName = this.unpackDomainName(counter);

        counter++; // Skip 0x00.

        this.unpackRest(counter);
    }

    private void unpackWithOffset() {
        int counter = 2; // Skipping the pointer bytes.

        this.unpackRest(counter);
    }

    private void unpackWithOffsetAndDomainName() {
        int counter = 0;

        while(this.binaryRepresentation[counter] < 0xC0) {
            counter++;
        }

        assert this.binaryRepresentation[counter] >= 0xC0;

        this.domainName = this.unpackDomainName(counter);

        counter+= 2; // Skip the pointer bytes.

        this.unpackRest(counter);
    }


    private void unpackRest(int counter){
        int typeCode = Utils.twoBytesToUnsignedInt(new byte[]{(byte)(this.binaryRepresentation[counter] & 0xFF), (byte)(this.binaryRepresentation[counter + 1] & 0xFF)});
        this.rDataType = DNSQuestionQTypeEnum.fromCode(typeCode); //This should be a different enum.

        counter += 2; // Skip the type.

        int classCode = Utils.twoBytesToUnsignedInt(new byte[]{(byte)(this.binaryRepresentation[counter] & 0xFF), (byte)(this.binaryRepresentation[counter + 1] & 0xFF)});
        this.rDataClass = DNSQuestionQClassEnum.fromCode(classCode); //This should be a different enum.

        counter += 2; // Skip the class.

        this.ttl = Utils.fourBytesToUnsignedInt(Arrays.copyOfRange(this.binaryRepresentation, counter, counter + 4));

        counter += 4; // Skip the ttl.

        this.rdLength = Utils.twoBytesToUnsignedInt(new byte[]{(byte)(this.binaryRepresentation[counter] & 0xFF), (byte)(this.binaryRepresentation[counter + 1] & 0xFF)});
        counter += 2;

        this.rData = Arrays.copyOfRange(this.binaryRepresentation, counter, counter + rdLength);

        assert this.binaryRepresentation.length == counter + rdLength;
    }

    private String unpackDomainName(int nullCharacterIndex) {
        byte[] data = Arrays.copyOfRange(this.binaryRepresentation, 0, nullCharacterIndex);
        int counter = 0;
        
        List<String> tokens = new ArrayList<>();

        while(counter < data.length) {
            int length = Utils.singleByteToUnsignedInt(data[counter]);

            tokens.add(new String(Arrays.copyOfRange(data, counter, counter + length)));

            counter += length;
        }

        tokens.forEach(this::validateTokenLength);

        return String.join(".", tokens);
    }

    private void validateTokenLength(String token) {
        assert token.length() <= 63;
    }
}
