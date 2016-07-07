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

    public static MyBodyPart fromPart(Part part) throws IOException, MessagingException {
        return MyBodyPart.simple(part);
    }

    public static MyBodyPart createMulti(String preamble, String mimeSubType, MyBodyPart... parts) throws MessagingException {
        BodyPart[] mbps = new MimeBodyPart[parts.length];
        for (int i = 0; i < parts.length; i++) {
            MyBodyPart part = parts[i];
            mbps[i] = part.getPart();
        }
        return createMulti(preamble, mimeSubType, mbps);
    }

    public static MyBodyPart createMulti(MyBodyPart... parts) throws MessagingException {
        return createMulti(null, "mixed", parts);
    }

    public MyBodyPart encrypt(MyBodyPart part, EncryptKey key) throws CryptoException, IOException, MessagingException {
        return encrypt(part.getPart(), key);
    }

    public MyBodyPart sign(MyBodyPart part, SignKey key) throws MessagingException, IOException, CryptoException {
        return sign(part.getPart(), key);
    }

    public MyBodyPart signDetached(MyBodyPart part, String preamble, SignKey key) throws MessagingException, CryptoException, IOException {
        return signDetached(part.getPart(), preamble, key);
    }

    public MyBodyPart signDetached(MyBodyPart part, SignKey key) throws MessagingException, CryptoException, IOException {
        return signDetached(part, "This is an S/MIME multipart signed message", key);
    }

    public MyBodyPart sign(MyBodyPart part, SignKey key, boolean detached) throws MessagingException, IOException, CryptoException {
        if (detached) {
            return signDetached(part, key);
        } else {
            return sign(part, key);
        }
    }

    public static MimeMessage toMessage(Session session, MyBodyPart myPart) throws MessagingException, IOException {
        MimeMessage result = new MimeMessage(session, MimeUtil.serialize(myPart.getPart()));
        result.saveChanges();
        return result;
    }
}
