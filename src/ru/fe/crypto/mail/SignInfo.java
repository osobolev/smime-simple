package ru.fe.crypto.mail;

import java.util.Date;
import java.util.Map;

public final class SignInfo {

    /**
     * Can be null
     */
    public final Date signDate;
    /**
     * Not null
     */
    public final Map<String, String> info;

    public SignInfo(Date signDate, Map<String, String> info) {
        this.signDate = signDate;
        this.info = info;
    }

    public String toString() {
        return info.toString();
    }
}
