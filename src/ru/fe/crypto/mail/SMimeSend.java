package ru.fe.crypto.mail;

import javax.mail.Address;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeMessage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

public final class SMimeSend {

    private final CryptoFactory factory;
    private final Session session = SMimeReceive.createFakeSession();

    public SMimeSend(CryptoFactory factory) {
        this.factory = factory;
    }

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

    private static void addHeaders(MimeMessage msg,
                                   Address from, Address[] to, String subject, String charset) throws MessagingException {
        msg.setSubject(subject, charset);
        msg.setFrom(from);
        for (Address address : to) {
            msg.addRecipient(Message.RecipientType.TO, address);
        }
    }

    public MimeMessage saveMail(Address from, Address[] to, String subject, String charset,
                                InputStreamSource src, String comment,
                                SignKey[] signCerts, EncryptKey encryptCert, boolean detachSignature) throws CryptoException, MessagingException, IOException {
        MimeMessage msg = createMessage(factory, session, charset, src, comment, signCerts, encryptCert, detachSignature);
        addHeaders(msg, from, to, subject, charset);
        return msg;
    }

    public static MimeMessage cosignMessage(CryptoFactory factory, Session session, MimeMessage message,
                                            SignKey[] signCerts, EncryptKey encryptCert) throws CryptoException, IOException, MessagingException {
        SignedPart sp = MailReader.decrypt(factory, message, true);
        if (sp.rawData == null)
            return null;
        MimeMessage msg = new MimeMessage(session);
        String data = MailWriter.fillMessage(factory, msg, message, null, null, null, sp, signCerts, encryptCert, sp.rawSignature != null);
        return MailWriter.finalizeMessage(session, msg, data);
    }

    public MimeMessage saveCosignedMail(Address from, Address[] to, String subject, String charset,
                                        MimeMessage source,
                                        SignKey[] signCerts, EncryptKey encryptCert) throws CryptoException, MessagingException, IOException {
        MimeMessage cosigned;
        if ((signCerts != null && signCerts.length > 0) || encryptCert != null) {
            cosigned = cosignMessage(factory, session, source, signCerts, encryptCert);
            if (cosigned == null)
                return null;
        } else {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            SignedPart.write(source, bos);
            cosigned = new MimeMessage(session, new ByteArrayInputStream(bos.toByteArray()));
        }
        addHeaders(cosigned, from, to, subject, charset);
        return cosigned;
    }
}
