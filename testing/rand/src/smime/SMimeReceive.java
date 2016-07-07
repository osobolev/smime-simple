package smime;

import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeMessage;
import java.io.IOException;
import java.util.Properties;

public final class SMimeReceive {

    public static SignedPart read(CryptoFactory factory, MimeMessage msg) throws CryptoException, IOException, MessagingException {
        return MailReader.decrypt(factory, msg, false);
    }

    public static Session createFakeSession() {
        Properties props = new Properties();
        return Session.getDefaultInstance(props);
    }
}
