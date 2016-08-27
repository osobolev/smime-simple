package smime;

import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeMessage;
import java.io.IOException;

public final class CoSignedMessage {

    private final SMimePart part;
    private final boolean signed;

    public CoSignedMessage(SMimePart part, boolean signed) {
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
        SMimePart signed = builder.sign(part, key, detached);
        return new CoSignedMessage(signed, true);
    }

    public CoSignedMessage encrypt(PartBuilder builder, EncryptKey key) throws IOException, MessagingException, CryptoException {
        SMimePart encrypted = builder.encrypt(part, key);
        return new CoSignedMessage(encrypted, signed);
    }
}
