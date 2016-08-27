package smime;

import javax.mail.BodyPart;
import javax.mail.MessagingException;
import javax.mail.Part;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import java.io.IOException;

public final class PartBuilder extends PartBuilderInternal {

    public PartBuilder(CryptoFactory factory) {
        super(factory);
    }

    public static SMimePart fromPart(Part part) throws IOException, MessagingException {
        return SMimePart.simple(part);
    }

    public static SMimePart createMulti(String preamble, String mimeSubType, SMimePart... parts) throws MessagingException {
        BodyPart[] mbps = new MimeBodyPart[parts.length];
        for (int i = 0; i < parts.length; i++) {
            SMimePart part = parts[i];
            mbps[i] = part.getPart();
        }
        return createMulti(preamble, mimeSubType, mbps);
    }

    public static SMimePart createMulti(SMimePart... parts) throws MessagingException {
        return createMulti(null, "mixed", parts);
    }

    public SMimePart encrypt(SMimePart part, EncryptKey key) throws CryptoException, IOException, MessagingException {
        return encrypt(part.getPart(), key);
    }

    public SMimePart sign(SMimePart part, SignKey key) throws MessagingException, IOException, CryptoException {
        return sign(part.getPart(), key);
    }

    public SMimePart signDetached(SMimePart part, String preamble, SignKey key) throws MessagingException, CryptoException, IOException {
        return signDetached(part.getPart(), preamble, key);
    }

    public SMimePart signDetached(SMimePart part, SignKey key) throws MessagingException, CryptoException, IOException {
        return signDetached(part, "This is an S/MIME multipart signed message", key);
    }

    public SMimePart sign(SMimePart part, SignKey key, boolean detached) throws MessagingException, IOException, CryptoException {
        if (detached) {
            return signDetached(part, key);
        } else {
            return sign(part, key);
        }
    }

    public static MimeMessage toMessage(Session session, SMimePart myPart) throws MessagingException, IOException {
        MimeMessage result = new MimeMessage(session, MimeUtil.serialize(myPart.getPart()));
        result.saveChanges();
        return result;
    }
}
