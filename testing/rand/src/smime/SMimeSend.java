package smime;

import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeMessage;
import java.io.IOException;
import java.util.List;

public final class SMimeSend {

    public static MimeMessage createMessage(CryptoFactory factory,
                                            Session session, String charset, InputStreamSource src, String comment,
                                            SignKey[] signCerts, EncryptKey encryptCert, boolean detachSignature) throws CryptoException, IOException, MessagingException {
        MimeMessage msg = new MimeMessage(session);
        String data = MailWriter.fillMessage(factory, msg, null, charset, src, comment, null, signCerts, encryptCert, detachSignature);
        return MailWriter.finalizeMessage(session, msg, data);
    }

    public static MimeMessage createMessage(CryptoFactory factory,
                                            Session session, String charset, InputStreamSource src, String comment,
                                            List<EnvelopeDesc> envelopes) throws CryptoException, IOException, MessagingException {
        MimeMessage msg = new MimeMessage(session);
        String data = MailWriter.signEncrypt(factory, msg, null, charset, src, comment, envelopes);
        return MailWriter.finalizeMessage(session, msg, data);
    }

    public static MimeMessage cosignMessage(CryptoFactory factory, Session session, MimeMessage message,
                                            SignKey[] signCerts, EncryptKey encryptCert) throws CryptoException, IOException, MessagingException {
        SignedPart sp = MailReader.decrypt(factory, message, true);
        if (sp.rawSignature == null)
            return null;
        MimeMessage msg = new MimeMessage(session);
        String data = MailWriter.fillMessage(factory, msg, message, null, null, null, sp, signCerts, encryptCert, sp.rawData != null);
        return MailWriter.finalizeMessage(session, msg, data);
    }
}
