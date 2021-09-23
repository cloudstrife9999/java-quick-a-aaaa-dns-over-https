package org.cloudstrife9999;

import org.cloudstrife9999.dns.DNSAdditional;
import org.cloudstrife9999.dns.DNSAnswer;
import org.cloudstrife9999.dns.DNSAuthority;
import org.cloudstrife9999.dns.DNSHeader;
import org.cloudstrife9999.dns.DNSQuestion;

public interface DNSMessage {
    public abstract byte[] getBytes();

    public abstract DNSHeader getHeader();

    public abstract DNSQuestion getQuestion();

    public abstract DNSAnswer getAnswer();

    public abstract DNSAuthority getAuthority();

    public abstract DNSAdditional getAdditional();

    public default byte[] getHeaderBytes() {
        return getHeader().getBytes();
    }

    public default byte[] getQuestionBytes() {
        return getQuestion().getBytes();
    }

    public default byte[] getAnswerBytes() {
        return getAnswer().getBytes();
    }

    public default byte[] getAuthorityBytes() {
        return getAuthority().getBytes();
    }

    public default byte[] getAdditionalBytes() {
        return getAdditional().getBytes();
    }
}
