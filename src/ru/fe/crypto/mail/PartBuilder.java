package ru.fe.crypto.mail;

import com.sun.mail.util.LineOutputStream;

import javax.mail.BodyPart;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;

public final class PartBuilder extends PartBuilderInternal {

    public PartBuilder(CryptoFactory factory) {
        super(factory);
    }

    public static MyBodyPart createMulti(MyBodyPart... parts) throws MessagingException {
        return createMulti(null, "mixed", parts);
    }

    public static MyBodyPart createMulti(String preamble, String mimeSubType, MyBodyPart... parts) throws MessagingException {
        BodyPart[] mbps = new MimeBodyPart[parts.length];
        for (int i = 0; i < parts.length; i++) {
            MyBodyPart part = parts[i];
            mbps[i] = part.getPart();
        }
        return createMulti(preamble, mimeSubType, mbps);
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

    private static MimeMessage writeMessage(Session session, MimeMessage message, InputStream data) throws MessagingException, IOException {
        BiByteArrayStream bis = new BiByteArrayStream();
        LineOutputStream los = new LineOutputStream(bis.output());
        MimeUtil.writeHeaders(message, los);
        MimeUtil.copyStreamEoln(data, los);
        los.flush();
        return new MimeMessage(session, bis.input());
    }

    public static MimeMessage toMessage(Session session, MyBodyPart myPart) throws MessagingException, IOException {
        MimeMessage message = new MimeMessage(session);

        MimeBodyPart part = myPart.getPart();
        Object content = part.getContent();
        MimeMessage result;
        if (content instanceof Multipart) {
            Multipart mp = (Multipart) content;
            message.setContent(mp);
            result = message;
        } else {
            message.saveChanges();
            Enumeration<?> headers = part.getAllHeaderLines();
            while (headers.hasMoreElements()) {
                String line = (String) headers.nextElement();
                message.addHeaderLine(line);
            }
            InputStream is = part.getRawInputStream(); // todo: do not use raw stream, write message headers/part whole
            // todo: this can be used for all types of content!
            try {
                result = writeMessage(session, message, is);
            } finally {
                MimeUtil.close(is);
            }
        }
        result.saveChanges();
        return result;
    }
}
