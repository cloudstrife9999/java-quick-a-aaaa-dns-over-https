package org.cloudstrife9999;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.net.ssl.HttpsURLConnection;

public class Doh {
    private static final String RESOLVER_IP = "1.1.1.1";
    private static final String RESOLVER_RESOURCE = "dns-query";
    private static final String GET_VARIABLE = "dns";
    private SecureRandom rng;

    public Doh() {
        this.rng = new SecureRandom();
    }

    public String[] resolveIPv4(String toResolve) throws IOException {
        byte[] qType = new byte[]{0x00, 0x01}; // A

        return resolveName(toResolve, qType);
    }

    public String[] resolveIPv6(String toResolve) throws IOException {
        byte[] qType = new byte[]{0x00, 0x1c}; // AAAA

        return resolveName(toResolve, qType);
    }

    private String[] resolveName(String toResolve, byte[] qType) throws IOException {
        byte[] transactionID = this.generateTransactionID();
        byte[] flags = new byte[]{0x01, 0x00};
        byte[] questions = new byte[]{0x00, 0x01};
        byte[] answerRRs = new byte[]{0x00, 0x00};
        byte[] authorityRRs = new byte[]{0x00, 0x00};
        byte[] additionalRRs = new byte[]{0x00, 0x00};
        byte[] qName = this.generateQNAME(toResolve);
        byte[] qClass = new byte[]{0x00, 0x01}; // IN

        ByteBuffer buffer = ByteBuffer.allocate(transactionID.length + flags.length + questions.length + answerRRs.length + authorityRRs.length + additionalRRs.length + qName.length + qType.length + qClass .length);
        buffer.put(transactionID);
        buffer.put(flags);
        buffer.put(questions);
        buffer.put(answerRRs);
        buffer.put(authorityRRs);
        buffer.put(additionalRRs);
        buffer.put(qName);
        buffer.put(qType);
        buffer.put(qClass);

        ByteBuffer queryForLaterComparision = ByteBuffer.allocate(qName.length + qType.length + qClass.length);
        queryForLaterComparision.put(qName);
        queryForLaterComparision.put(qType);
        queryForLaterComparision.put(qClass);

        return doQuery(buffer.array(), transactionID, queryForLaterComparision.array(), qType);
    }

    private String[] doQuery(byte[] data, byte[] transactionID, byte[] queryForLaterComparision, byte[] qType) throws IOException {
        URL url = this.buildURL(data);
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();

        connection.setDoOutput(true);
        connection.setRequestMethod("GET");
        connection.setRequestProperty("User-Agent", "Android");
        connection.setRequestProperty("Accept", "application/dns-message");

        byte[] responseBytes = new byte[connection.getInputStream().available()];
        
        if(connection.getInputStream().read(responseBytes) > 0) {
            return this.parseResponse(responseBytes, transactionID, queryForLaterComparision, qType);
        }
        else {
            return new String[]{"No data returned"};
        }
    }

    private String[] parseResponse(byte[] responseBytes, byte[] transactionID, byte[] queryForLaterComparision, byte[] qType) {
        try {
            this.verifyTransactionID(responseBytes, transactionID);
            this.verifyFlags(responseBytes);
            this.verifyNumberOfQuestions(responseBytes);

            short numberOfAnswers = this.getNumberOfAnswers(responseBytes);

            this.verifyQuery(responseBytes, queryForLaterComparision);

            return parseAnswers(responseBytes, queryForLaterComparision, numberOfAnswers, qType);

        }
        catch(IOException e) {
            return new String[]{"Internal Error due to: " + e.getMessage()};
        }
    }

    private String[] parseAnswers(byte[] responseBytes, byte[] queryForLaterComparision, short numberOfAnswers, byte[] qType) throws IOException {
        String[] answers = new String[numberOfAnswers];
        int runningIndex = 14 + queryForLaterComparision.length;

        for(short i=0; i<numberOfAnswers; i++) {
            if (!this.matchQType(responseBytes, qType, runningIndex)) {
                runningIndex += 8;
                short contentLength = this.bytesToShort(responseBytes[runningIndex], responseBytes[runningIndex + 1]);
                runningIndex += 2 + contentLength;
            }
            else {
                runningIndex += 2;
                this.verifyINClass(responseBytes, runningIndex);
                runningIndex += 6;
                short contentLength = this.bytesToShort(responseBytes[runningIndex], responseBytes[runningIndex + 1]);
                runningIndex += 2;
                answers[i] = this.parseAnswer(responseBytes, qType, runningIndex, contentLength);
                runningIndex += contentLength;
            }
        }

        return answers;
    }

    private String parseIPv4(byte[] responseBytes, int runningIndex, short contentLength) throws UnknownHostException {
        if(contentLength != 4) {
            return "Not found";
        }
        else {
            byte[] ipBytes = Arrays.copyOfRange(responseBytes, runningIndex, runningIndex + contentLength);

            Inet4Address address = (Inet4Address) InetAddress.getByAddress(ipBytes);

            return address.getHostAddress();
        }
    }

    private String parseIPv6(byte[] responseBytes, int runningIndex, short contentLength) throws UnknownHostException {
        if(contentLength == 0) {
            return "Not found";
        }
        else {
            byte[] ipBytes = Arrays.copyOfRange(responseBytes, runningIndex, runningIndex + contentLength);

            Inet6Address address = (Inet6Address) InetAddress.getByAddress(ipBytes);

            return address.getHostAddress();
        }
    }

    private String parseAnswer(byte[] responseBytes, byte[] qType, int runningIndex, short contentLength) throws UnknownHostException {
        if ((qType[1] & 0xFF) == 0x01) { // A
            return this.parseIPv4(responseBytes, runningIndex, contentLength);
        }
        else if ((qType[1] & 0xFF) == 0x1c) { // AAAA
            return this.parseIPv6(responseBytes, runningIndex, contentLength);
        }
        else {
            throw new IllegalArgumentException();
        }
    }

    private void verifyINClass(byte[] responseBytes, int runningIndex) throws IOException {
        if ((responseBytes[runningIndex] & 0xFF) != 0x00 || (responseBytes[runningIndex + 1] & 0xFF) != 0x01) {
            throw new IOException("The class of the response is not IN.");
        }
    }

    private boolean matchQType(byte[] responseBytes, byte[] qType, int runningIndex) {
        return (responseBytes[runningIndex] & 0xFF) == qType[0] && (responseBytes[runningIndex + 1] & 0xFF) == qType[1];
    }

    private void verifyQuery(byte[] responseBytes, byte[] queryForLaterComparision) throws IOException {
        if (!Arrays.equals(Arrays.copyOfRange(responseBytes, 12, 12 + queryForLaterComparision.length), queryForLaterComparision)) {
            throw new IOException("The original query does not match the query in the response message.");
        }
    }

    private short getNumberOfAnswers(byte[] responseBytes) {
        return this.bytesToShort(responseBytes[6], responseBytes[7]);
    }

    private short bytesToShort(byte high, byte low) {
        return (short)(((high & 0xFF) << 8) | (low & 0xFF));
    }

    private void verifyNumberOfQuestions(byte[] responseBytes) throws IOException {
        if ((responseBytes[4] & 0xFF) != 0x00 || (responseBytes[5] & 0xFF) != 0x01) {
            throw new IOException("The number of questions in the query messages does not match the number of questions in the response message.");
        }
    }

    private void verifyTransactionID(byte[] responseBytes, byte[] transactionID) throws IOException {
        if (responseBytes[0] != transactionID[0] || responseBytes[1] != transactionID[1]) {
            throw new IOException("The transaction IDs of query and response messages do not match.");
        }
    }

    private void verifyFlags(byte[] responseBytes) throws IOException {
        if ((responseBytes[2] & 0xFF) != 0x81 || (responseBytes[3] & 0xFF) != 0x80) {
            throw new IOException("The flags of the response messages signal an error."); // Not strictly true.
        }
    }

    private URL buildURL(byte[] data) throws IOException {
        try {
            StringBuilder builder = new StringBuilder();
            builder.append("https://");
            builder.append(Doh.RESOLVER_IP);
            builder.append("/");
            builder.append(Doh.RESOLVER_RESOURCE);
            builder.append("?");
            builder.append(Doh.GET_VARIABLE);
            builder.append("=");
            builder.append(Base64.getUrlEncoder().withoutPadding().encodeToString(data));

            return new URL(builder.toString());
        }
        catch(MalformedURLException e) {
            throw new IOException(e);
        }
    }

    private byte[] generateTransactionID() {
        byte[] transactionID = new byte[2];
        this.rng.nextBytes(transactionID);

        return transactionID;
    }

    private byte[] generateQNAME(String toResolve) {
        ByteBuffer buffer = ByteBuffer.allocate(toResolve.length() + 2);

        for(String token: toResolve.split("\\.")) {
            buffer.put(this.getTokenWithLengthPrefix(token));
        }

        buffer.put(new byte[]{0x00});

        return buffer.array();
    }

    private byte[] getTokenWithLengthPrefix(String token) {
        byte length = (byte) (token.length() & 0xFF);

        ByteBuffer buffer = ByteBuffer.allocate(token.getBytes().length + 1);
        buffer.put(length);
        buffer.put(token.getBytes());

        return buffer.array();
    }
}
