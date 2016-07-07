package smime.rand;

import javax.mail.internet.MimeMessage;

public final class RandomMessage {

    public final MimeMessage message;
    public final boolean oldCompatible;
    public final String description;
    public final boolean signed;

    RandomMessage(MimeMessage message, boolean oldCompatible, String description, boolean signed) {
        this.message = message;
        this.oldCompatible = oldCompatible;
        this.description = description;
        this.signed = signed;
    }
}
