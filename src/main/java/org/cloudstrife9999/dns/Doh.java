package org.cloudstrife9999.dns;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;

import org.cloudstrife9999.dns.question.DNSQuestionQTypeEnum;

public class Doh {
    private static final String RESOLVER_IP = "1.1.1.1";
    private static final String RESOLVER_RESOURCE = "dns-query";
    private static final String GET_VARIABLE = "dns";

    public List<String> resIPv4(String toResolve) throws IOException {
        DNSMessage queryMessage = DNSMessage.quickIPv4QueryMessage(toResolve);

        return this.doQuery(queryMessage.getBytes(), queryMessage.getHeader().getTransactionID(), queryMessage.getQuestions().get(0).getQType().getCodeBytes());
    }

    public List<String> resIPv6(String toResolve) throws IOException {
        DNSMessage queryMessage = DNSMessage.quickIPv6QueryMessage(toResolve);

        return this.doQuery(queryMessage.getBytes(), queryMessage.getHeader().getTransactionID(), queryMessage.getQuestions().get(0).getQType().getCodeBytes());
    }

    private List<String> doQuery(byte[] data, byte[] transactionID, byte[] qType) throws IOException {
        URL url = this.buildURL(data);
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();

        connection.setDoOutput(true);
        connection.setRequestMethod("GET");
        connection.setRequestProperty("User-Agent", "Java Client");
        connection.setRequestProperty("Accept", "application/dns-message");

        byte[] responseBytes = new byte[connection.getInputStream().available()];
        
        if(connection.getInputStream().read(responseBytes) > 0) {
            DNSMessage message = new DNSMessage(responseBytes);

            assert Arrays.equals(message.getHeader().getTransactionID(), transactionID);

            return parseResponseMessage(message, qType);
        }
        else {
            return Arrays.asList("No data returned");
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
}
