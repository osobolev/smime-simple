package smime.rand;

import javax.mail.internet.MimeMessage;

public final class RandomMessage {

    public final String fileName;
    public final String content;
    public final MimeMessage message;
    public final boolean oldCompatible;
    public final String description;
    public final boolean signed;

    public RandomMessage(String fileName, String content, MimeMessage message, boolean oldCompatible, String description, boolean signed) {
        this.fileName = fileName;
        this.content = content;
        this.message = message;
        this.oldCompatible = oldCompatible;
        this.description = description;
        this.signed = signed;
    }
}
