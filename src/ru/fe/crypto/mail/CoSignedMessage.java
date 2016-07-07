package ru.fe.crypto.mail;

import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import java.io.IOException;

public final class CoSignedMessage {

    private final MyBodyPart part;
    private final boolean signed;

    public CoSignedMessage(MyBodyPart part, boolean signed) {
        this.part = part;
        this.signed = signed;
    }

    public boolean isSigned() {
        return signed;
    }

    public MimeMessage getMessage(Session session) throws IOException, MessagingException {
        return PartBuilder.toMessage(session, part);
    }

    public CoSignedMessage sign(PartBuilder builder, SignKey key, boolean detached) throws IOException, MessagingException, CryptoException {
        MyBodyPart signed = builder.sign(part, key, detached);
        return new CoSignedMessage(signed, true);
    }

    public CoSignedMessage encrypt(PartBuilder builder, EncryptKey key) throws IOException, MessagingException, CryptoException {
        MyBodyPart encrypted = builder.encrypt(part, key);
        return new CoSignedMessage(encrypted, signed);
    }
}
