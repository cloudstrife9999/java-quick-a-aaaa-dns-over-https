package org.cloudstrife9999.dns.common;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.cloudstrife9999.dns.question.DNSQuestionQClassEnum;
import org.cloudstrife9999.dns.question.DNSQuestionQTypeEnum;
import org.cloudstrife9999.dns.record.DNSAdditional;
import org.cloudstrife9999.dns.record.DNSAnswer;
import org.cloudstrife9999.dns.record.DNSAuthority;
import org.cloudstrife9999.dns.record.DNSRecordEnum;

public class DNSMessage {
    private byte[] representation;
    private DNSHeader header;
    private List<DNSQuestion> questions;
    private List<DNSAnswer> answers;
    private List<DNSAuthority> authorities;
    private List<DNSAdditional> additionals;

    public DNSMessage(DNSHeader header, DNSQuestion question, DNSAnswer answer, DNSAuthority authority, DNSAdditional additional) {
        this.header = header;

        this.questions = new ArrayList<>();
        this.answers = new ArrayList<>();
        this.authorities = new ArrayList<>();
        this.additionals = new ArrayList<>();

        this.questions.add(question);
        this.answers.add(answer);
        this.authorities.add(authority);
        this.additionals.add(additional);

        pack();
    }

    public DNSMessage(DNSHeader header, DNSQuestion question) {
        this.header = header;

        this.questions = new ArrayList<>();
        this.answers = new ArrayList<>();
        this.authorities = new ArrayList<>();
        this.additionals = new ArrayList<>();

        this.questions.add(question);

        pack();
    }

    public DNSMessage(byte[] representation) {
        this.representation = representation;
        this.questions = new ArrayList<>();
        this.answers = new ArrayList<>();
        this.authorities = new ArrayList<>();
        this.additionals = new ArrayList<>();

        try {
            if (representation != null && representation.length > DNSHeader.HEADER_LENGTH) {

                this.header = new DNSHeader(Arrays.copyOfRange(representation, 0, DNSHeader.HEADER_LENGTH));

                unpack(Arrays.copyOfRange(representation, DNSHeader.HEADER_LENGTH, representation.length));
            }
            else {
                throw new IllegalArgumentException("Malformed DNS message.");
            }
        }
        catch(Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static DNSMessage quickIPv4QueryMessage(String toResolve) {
        DNSQuestion question = new DNSQuestion(toResolve, DNSQuestionQTypeEnum.A, DNSQuestionQClassEnum.IN);
        DNSHeader header = DNSHeader.quickHeaderForQuery();

        return new DNSMessage(header, question);
    }

    public static DNSMessage quickIPv6QueryMessage(String toResolve) {
        DNSQuestion question = new DNSQuestion(toResolve, DNSQuestionQTypeEnum.AAAA, DNSQuestionQClassEnum.IN);
        DNSHeader header = DNSHeader.quickHeaderForQuery();
        
        return new DNSMessage(header, question);
    }

    public byte[] getBytes() {
        if (this.representation == null){
            return new byte[]{};
        }
        else {
            return this.representation;
        }
    }

    public DNSHeader getHeader() {
        return this.header;
    }

    public List<DNSQuestion> getQuestions() {
        return this.questions;
    }

    public List<DNSAnswer> getAnswers() {
        return this.answers;
    }

    public List<DNSAuthority> getAuthorities() {
        return this.authorities;
    }

    public List<DNSAdditional> getAdditionals() {
        return this.additionals;
    }

    public byte[] getHeaderBytes() {
        if(this.header == null) {
            return new byte[]{};
        }
        else {
            return this.header.getBytes();
        }
    }

    public byte[] getQuestionBytes() {
        if(this.questions.isEmpty()) {
            return new byte[]{};
        }
        else {
            int size = this.questions.stream().map(DNSQuestion::getBytes).map(elm -> elm.length).reduce(0, Integer::sum);
            ByteBuffer buffer = ByteBuffer.allocate(size);

            this.questions.stream().map(DNSQuestion::getBytes).forEach(buffer::put);

            return buffer.array();
        }
    }

    public byte[] getAnswerBytes() {
        if(this.answers.isEmpty()) {
            return new byte[]{};
        }
        else {
            int size = this.answers.stream().map(DNSAnswer::getBytes).map(elm -> elm.length).reduce(0, Integer::sum);
            ByteBuffer buffer = ByteBuffer.allocate(size);

            this.answers.stream().map(DNSAnswer::getBytes).forEach(buffer::put);

            return buffer.array();
        }
    }

    public byte[] getAuthorityBytes() {
        if(this.authorities.isEmpty()) {
            return new byte[]{};
        }
        else {
            int size = this.authorities.stream().map(DNSAuthority::getBytes).map(elm -> elm.length).reduce(0, Integer::sum);
            ByteBuffer buffer = ByteBuffer.allocate(size);

            this.authorities.stream().map(DNSAuthority::getBytes).forEach(buffer::put);

            return buffer.array();
        }
    }

    public byte[] getAdditionalBytes() {
        if(this.additionals.isEmpty()) {
            return new byte[]{};
        }
        else {
            int size = this.additionals.stream().map(DNSAdditional::getBytes).map(elm -> elm.length).reduce(0, Integer::sum);
            ByteBuffer buffer = ByteBuffer.allocate(size);

            this.additionals.stream().map(DNSAdditional::getBytes).forEach(buffer::put);

            return buffer.array();
        }
    }

    private void pack() {
        byte[] h = this.getHeaderBytes();
        byte[] q = this.getQuestionBytes();
        byte[] an = this.getAnswerBytes();
        byte[] au = this.getAuthorityBytes();
        byte[] ad = this.getAdditionalBytes();

        ByteBuffer buffer = ByteBuffer.allocate(h.length + q.length + an.length + au.length + ad.length);

        buffer.put(h);
        buffer.put(q);
        buffer.put(an);
        buffer.put(au);
        buffer.put(ad);

        this.representation = buffer.array();
    }

    private void unpack(byte[] headerlessMessage) {
        byte[] leftovers = this.unpackQuestion(headerlessMessage);
        leftovers = this.unpackAnswer(leftovers);
        leftovers = this.unpackAuthority(leftovers);
        leftovers = this.unpackAdditional(leftovers);

        assert leftovers.length == 0;

        this.setDomainNamesViaPointers();
    }

    private void setDomainNamesViaPointers() {
        for(DNSAnswer answer : this.answers) {
            if(answer.getDomainName() == null) {
                int offset = answer.getOffset();
                int nullCharacterIndex = this.getFirstNullCharacterIndexStartingAt(offset);
                String domainName = this.unpackDomainName(offset, nullCharacterIndex);
                answer.setDomainName(domainName);
            }
        }

        for(DNSAuthority authority : this.authorities) {
            if(authority.getDomainName() == null) {
                int offset = authority.getOffset();
                int nullCharacterIndex = this.getFirstNullCharacterIndexStartingAt(offset);
                String domainName = this.unpackDomainName(offset, nullCharacterIndex);
                authority.setDomainName(domainName);
            }
        }

        for(DNSAdditional additional : this.additionals) {
            if(additional.getDomainName() == null) {
                int offset = additional.getOffset();
                int nullCharacterIndex = this.getFirstNullCharacterIndexStartingAt(offset);
                String domainName = this.unpackDomainName(offset, nullCharacterIndex);
                additional.setDomainName(domainName);
            }
        }
    }

    private int getFirstNullCharacterIndexStartingAt(int offset) {
        for(int i=offset; i<this.representation.length; i++) {
            if(this.representation[i] == 0x00) {
                return i;
            }
        }

        throw new IllegalArgumentException();
    }

    private String unpackDomainName(int start, int end) {
        byte[] data = Arrays.copyOfRange(this.representation, start, end);
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

    // Assuming there is only 1 question (because that is what the API allows for).
    private byte[] unpackQuestion(byte[] data) {
        assert this.header.getQdCount() == 1;
        assert data.length > 0;

        int counter = 0;
        List<String> tokens = new ArrayList<>();
        
        while(data.length > counter && data[counter] != (byte)(0x00 & 0xFF)) {
            int length = data[counter];
            counter += 1;
            byte[] tmp = Arrays.copyOfRange(data, counter, counter + length);
            tokens.add(new String(tmp));
            counter += length;
        }

        String domainName = String.join(".", tokens);

        // Skipping the 0x00 that signals the end of the domain name (which is in data[counter]).
        int qTypeCode = Utils.twoBytesToUnsignedInt(Arrays.copyOfRange(data, counter + 1, counter + 3));
        int qClassCode = Utils.twoBytesToUnsignedInt(Arrays.copyOfRange(data, counter + 3, counter + 5));

        this.questions.add(new DNSQuestion(domainName, DNSQuestionQTypeEnum.fromCode(qTypeCode), DNSQuestionQClassEnum.fromCode(qClassCode)));

        return Arrays.copyOfRange(data, counter + 5, data.length);
    }

    private byte[] unpackAnswer(byte[] data) {
        int numberOfElements = this.header.getAnCount();

        return unpackRecord(data, numberOfElements, DNSRecordEnum.ANSWER);
    }

    private byte[] unpackAuthority(byte[] data) {
        int numberOfElements = this.header.getNsCount();

        return unpackRecord(data, numberOfElements, DNSRecordEnum.AUTHORITY);
    }

    private byte[] unpackAdditional(byte[] data) {
        int numberOfElements = this.header.getArCount();

        return unpackRecord(data, numberOfElements, DNSRecordEnum.ADDITIONAL);
    }

    private byte[] unpackRecord(byte[] data, int numberOfElements, DNSRecordEnum recordType) {
        int counter = 0;

        for(int i=0; i<numberOfElements; i++) {
            assert(counter < data.length);
            counter = this.unpackSingleRecordElement(data, counter, recordType);
        }

        return Arrays.copyOfRange(data, counter, data.length);
    }

    private int unpackSingleRecordElement(byte[] data, int counter, DNSRecordEnum recordType) {
        if (Utils.singleByteToUnsignedInt(data[counter]) >= 0xC0) {
            return this.unpackSingleRecordElementStartingWithPointer(data, counter,recordType);
        }
        else if (this.usingReservedCombination(data[counter])) {
            throw new IllegalArgumentException("Illegal combination of the first two bits in a DNS record.");
        }
        else {
            return this.unpackSingleRecordElementWithDomain(data, counter, recordType);
        }
    }

    private boolean usingReservedCombination(byte b) {
        return (b >> 6) == 0x10 || (b >> 6) == 0x01; 
    }

    private int unpackSingleRecordElementStartingWithPointer(byte[] data, int counter, DNSRecordEnum recordType) {
        int start = counter;
        int pointerIndex = counter;

        assert data[pointerIndex] >= 0xC0;

        int offset = this.findOffset(data, pointerIndex);
        counter += 2; // Skipping the pointer.
        counter += 2; // Skipping the type.
        counter += 2; // Skipping the class.
        counter += 4; // Skipping the ttl.

        int rdLength = Utils.twoBytesToUnsignedInt(new byte[]{(byte)(data[counter] & 0xFF), (byte)(data[counter + 1] & 0xFF)});

        counter += 2; // Skipping the rdLength bytes.

        int end = counter + rdLength; // Index of the first byte of the next element/record. 

        byte[] bytes = Arrays.copyOfRange(data, start, end);

        this.addElementToAppropriateList(bytes, recordType, offset, false);

        return end; // Index of the first byte of the next element/record.
    }

    private int unpackSingleRecordElementWithDomain(byte[] data, int counter, DNSRecordEnum recordType) {
        if(this.endsWithNullCharacter(data, counter)) {
            return this.unpackSingleRecordElementWithDomainAndNullCharacter(data, counter, recordType);
        }
        else {
            return this.unpackSingleRecordElementWithDomainAndPointer(data, counter, recordType);
        }
    }

    private boolean endsWithNullCharacter(byte[] data, int counter) {
        for(int i=counter; i<data.length; i++) {
            if(data[counter] == 0x00) {
                return true;
            }
            else if(data[counter] >= 0xC0) {
                return false;
            }
        }

        throw new IllegalArgumentException("Malformed DNS record.");
    }

    private int unpackSingleRecordElementWithDomainAndNullCharacter(byte[] data, int counter, DNSRecordEnum recordType) {
        int start = counter;

        while(data[counter] != 0x00) {
            counter++;
        }

        assert data[counter] == 0x00;

        int end = this.determineEndOfRecordElementHavingANullByte(data, counter);

        byte[] bytes = Arrays.copyOfRange(data, start, end);

        this.addElementToAppropriateList(bytes, recordType);

        return end; // Index of the first byte of the next element/record.
    }

    // No pointer whatsoever + null byte at the end.
    private int determineEndOfRecordElementHavingANullByte(byte[] data, int nullBytePosition) {
        assert data[nullBytePosition] == 0x00;

        int counter = nullBytePosition;

        counter += 1; // Skipping the 0x00.
        counter += 8; // Ignoring for now type, class, and ttl.

        int rdLength = Utils.twoBytesToUnsignedInt(new byte[]{(byte)(data[counter] & 0xFF), (byte)(data[counter + 1] & 0xFF)});

        counter += 2; // Skipping the rdLength bytes.

        return counter + rdLength; // Index of the first byte of the next element/record. 
    }

    // No null byte + pointer at the end.
    private int determineEndOfRecordElementHavingPointerAtTheEnd(byte[] data, int pointerFirstBytePosition) {
        assert data[pointerFirstBytePosition] >= 0xC0;

        int counter = pointerFirstBytePosition;

        counter += 2; // Skipping the pointer.
        counter += 8; // Ignoring for now type, class, and ttl.

        int rdLength = Utils.twoBytesToUnsignedInt(new byte[]{(byte)(data[counter] & 0xFF), (byte)(data[counter + 1] & 0xFF)});

        counter += 2; // Skipping the rdLength bytes.

        return counter + rdLength; // Index of the first byte of the next element/record. 
    }

    private int unpackSingleRecordElementWithDomainAndPointer(byte[] data, int counter, DNSRecordEnum recordType) {
        int start = counter;

        while(data[counter] < 0xC0) {
            counter++;
        }

        assert data[counter] >= 0xC0;

        int pointerIndex = counter;
        int offset = this.findOffset(data, pointerIndex);
        int end = this.determineEndOfRecordElementHavingPointerAtTheEnd(data, pointerIndex);
        byte[] bytes = Arrays.copyOfRange(data, start, end);

        this.addElementToAppropriateList(bytes, recordType, offset, true);

        return end; // Index of the first byte of the next element/record.
    }

    private int findOffset(byte[] data, int pointerIndex) {
        byte[] pointerData = new byte[]{(byte)(data[pointerIndex] & 0xFF), (byte)(data[pointerIndex + 1] & 0xFF)};

        return Utils.twoBytesToUnsignedInt(pointerData) - 0xC000;
    }

    private void addElementToAppropriateList(byte[] bytes, DNSRecordEnum recordType) {
        switch(recordType){
            case ANSWER:
                this.answers.add(new DNSAnswer(bytes));
                break;
            case AUTHORITY:
                this.authorities.add(new DNSAuthority(bytes));
                break;
            case ADDITIONAL:
                this.additionals.add(new DNSAdditional(bytes));
                break;
            default:
                throw new IllegalArgumentException();
        }
    }

    private void addElementToAppropriateList(byte[] bytes, DNSRecordEnum recordType, int offset, boolean hasDomainName) {
        switch(recordType){
            case ANSWER:
                this.answers.add(new DNSAnswer(bytes, offset, hasDomainName));
                break;
            case AUTHORITY:
                this.authorities.add(new DNSAuthority(bytes, offset, hasDomainName));
                break;
            case ADDITIONAL:
            this.additionals.add(new DNSAdditional(bytes, offset, hasDomainName));
                break;
            default:
                throw new IllegalArgumentException();
        }
    }
}
