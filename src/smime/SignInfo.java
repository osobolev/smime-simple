package smime;

import java.util.Date;
import java.util.Map;

public final class SignInfo {

    /**
     * Can be null
     */
    public final Date signDate;
    /**
     * Cannot be null
     */
    public final Map<String, String> info;
    public final boolean verified;
    /**
     * Can be null
     */
    public final Exception error; // todo: change to String???

    public SignInfo(Date signDate, Map<String, String> info, boolean verified, Exception error) {
        this.signDate = signDate;
        this.info = info;
        this.verified = verified;
        this.error = error;
    }

    public String toString() {
        return info.toString();
    }
}
