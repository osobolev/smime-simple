package ru.fe.crypto.mail;

import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import java.io.IOException;

public final class CoSignedMessage {

    private final MimeMessage message;
    private final MimeBodyPart part;
    private final boolean signed;

    CoSignedMessage(MimeMessage message, MimeBodyPart part, boolean signed) {
        this.message = message;
        this.part = part;
        this.signed = signed;
    }

    public boolean isSigned() {
        return signed;
    }

    public MimeMessage getMessage(Session session) throws IOException, MessagingException {
        if (message != null) {
            return message;
        } else {
            return PartBuilder.toMessage(session, part);
        }
    }

    private MimeBodyPart getPart() throws IOException, MessagingException {
        if (message != null) {
            return PartBuilder.messageToPart(message);
        } else {
            return part;
        }
    }

    public CoSignedMessage sign(PartBuilder builder, SignKey key, boolean detached) throws IOException, MessagingException, CryptoException {
        MimeBodyPart mbp = getPart();
        MimeBodyPart signed = builder.sign(mbp, key, detached);
        return new CoSignedMessage(null, signed, true);
    }

    public CoSignedMessage encrypt(PartBuilder builder, EncryptKey key) throws IOException, MessagingException, CryptoException {
        MimeBodyPart mbp = getPart();
        MimeBodyPart encrypted = builder.encrypt(mbp, key);
        return new CoSignedMessage(null, encrypted, signed);
    }
}
