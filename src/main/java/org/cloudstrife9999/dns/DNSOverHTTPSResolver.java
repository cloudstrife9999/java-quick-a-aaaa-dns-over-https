package org.cloudstrife9999.dns;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;

import org.cloudstrife9999.dns.common.DNSMessage;
import org.cloudstrife9999.dns.common.Utils;
import org.cloudstrife9999.dns.question.DNSQuestionQTypeEnum;
import org.cloudstrife9999.dns.record.DNSAnswer;

public class DNSOverHTTPSResolver {
    private static final String RESOLVER_IP = "1.1.1.1";
    private static final String RESOLVER_RESOURCE = "dns-query";
    private static final String GET_VARIABLE = "dns";
    private String userAgent;
    private String accept;
    private String method;

    public DNSOverHTTPSResolver(){
        this("Java Client");
    }

    public DNSOverHTTPSResolver(String customUA){
        if(customUA == null || "".equals(customUA)) {
            throw new IllegalArgumentException("A null or empty User-Agent string was provided");
        }

        this.userAgent = customUA;
        this.accept = "application/dns-message";
        this.method = "GET";
    }

    public List<String> resolveToIPv4(String toResolve) throws IOException {
        DNSMessage queryMessage = DNSMessage.quickIPv4QueryMessage(toResolve);

        return this.doQuery(queryMessage.getBytes(), queryMessage.getHeader().getTransactionID(), queryMessage.getQuestions().get(0).getQType().getCodeBytes());
    }

    public List<String> resolveToIPv6(String toResolve) throws IOException {
        DNSMessage queryMessage = DNSMessage.quickIPv6QueryMessage(toResolve);

        return this.doQuery(queryMessage.getBytes(), queryMessage.getHeader().getTransactionID(), queryMessage.getQuestions().get(0).getQType().getCodeBytes());
    }

    private List<String> doQuery(byte[] data, byte[] transactionID, byte[] qType) throws IOException {
        URL url = this.buildURL(data);
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();

        connection.setDoOutput(true);
        connection.setRequestMethod(this.method);
        connection.setRequestProperty("User-Agent", this.userAgent);
        connection.setRequestProperty("Accept", this.accept);

        byte[] responseBytes = new byte[connection.getInputStream().available()];
        
        if(connection.getInputStream().read(responseBytes) > 0) {
            DNSMessage message = new DNSMessage(responseBytes);

            assert Arrays.equals(message.getHeader().getTransactionID(), transactionID);

            return parseResponseMessage(message, qType);
        }
        else {
            return Collections.emptyList();
        }
    }

    private List<String> parseResponseMessage(DNSMessage message, byte[] qType) throws IOException {
        DNSQuestionQTypeEnum type = DNSQuestionQTypeEnum.fromCode(Utils.twoBytesToUnsignedInt(qType));
        
        List<String> answers = new ArrayList<>();

        for(DNSAnswer answer: message.getAnswers()) {

            if(type.refersToAnAQuery() && answer.getrDataType().refersToAnAResponse()){
                answers.add(answer.getRDataAsIPv4());
            }
            else if(type.refersToAnAAAAQuery() && answer.getrDataType().refersToAnAAAAResponse()) {
                answers.add(answer.getRDataAsIPv6());
            }
        }

        return answers;
    }

    private URL buildURL(byte[] data) throws IOException {
        try {
            StringBuilder builder = new StringBuilder();
            builder.append("https://");
            builder.append(DNSOverHTTPSResolver.RESOLVER_IP);
            builder.append("/");
            builder.append(DNSOverHTTPSResolver.RESOLVER_RESOURCE);
            builder.append("?");
            builder.append(DNSOverHTTPSResolver.GET_VARIABLE);
            builder.append("=");
            builder.append(Base64.getUrlEncoder().withoutPadding().encodeToString(data));

            return new URL(builder.toString());
        }
        catch(MalformedURLException e) {
            throw new IOException(e);
        }
    }
}
