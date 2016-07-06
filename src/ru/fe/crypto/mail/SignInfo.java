package ru.fe.crypto.mail;

import java.util.Date;
import java.util.Map;

public final class SignInfo {

    /**
     * Can be null
     */
    public final Date signDate;
    /**
     * Can be null
     */
    public final Map<String, String> info;
    public final boolean verified;

    public SignInfo(Date signDate, Map<String, String> info, boolean verified) {
        this.signDate = signDate;
        this.info = info;
        this.verified = verified;
    }

    public String toString() {
        return info == null ? "-" : info.toString();
    }
}
