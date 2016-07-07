package smime.test;

import javax.mail.internet.MimeMessage;

final class RandomMessage {

    final MimeMessage message;
    final boolean oldCompatible;
    final String description;
    final boolean signed;

    RandomMessage(MimeMessage message, boolean oldCompatible, String description, boolean signed) {
        this.message = message;
        this.oldCompatible = oldCompatible;
        this.description = description;
        this.signed = signed;
    }
}
