package ru.fe.crypto.mail;

import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.Session;
import javax.mail.internet.*;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

// todo: simple sign, if not signed before
public final class CoSignWalker {

    private final CryptoFactory factory;
    private final PartBuilder builder;
    private final SignKey addKey;

    public CoSignWalker(CryptoFactory factory, PartBuilder builder, SignKey addKey) {
        this.factory = factory;
        this.builder = builder;
        this.addKey = addKey;
    }

    public MimeMessage walk(Session session, MimeMessage message) throws MessagingException, IOException, CryptoException {
        MimePart part = walk(message);
        MimeMessage cosigned;
        if (part instanceof MimeBodyPart) {
            MimeBodyPart mbp = (MimeBodyPart) part;
            cosigned = PartBuilder.toMessage(session, mbp);
        } else {
            cosigned = message;
        }
        cosigned.saveChanges();
        // todo: add new encryption if necessary
        return cosigned;
    }

    private Crypto getCrypto() {
        return factory.getCrypto();
    }

    @SuppressWarnings("TailRecursion")
    private MimePart walk(MimePart part) throws MessagingException, IOException, CryptoException {
        if (part.isMimeType("multipart/signed")) {
            builder.cosignDetached(part, addKey);
            return part;
        } else if (part.isMimeType("application/pkcs7-mime")) {
            ContentType contentType = new ContentType(part.getContentType());
            String smime = contentType.getParameter("smime-type");
            if ("signed-data".equals(smime)) {
                return builder.cosign(part, addKey);
            } else {
                InputStream is = part.getInputStream();
                String decrypted;
                try {
                    decrypted = getCrypto().decryptData(is);
                } finally {
                    MimeUtil.close(is);
                }
                return walk(new MimeBodyPart(new ByteArrayInputStream(decrypted.getBytes())));
            }
        } else if (part.isMimeType("multipart/*")) {
            Multipart mp = (Multipart) part.getContent();
            MimeMultipart newMp = null;
            int count = mp.getCount();
            for (int i = 0; i < count; i++) {
                MimeBodyPart child = (MimeBodyPart) mp.getBodyPart(i);
                MimeBodyPart newChild = (MimeBodyPart) walk(child);
                if (newMp != null) {
                    newMp.addBodyPart(newChild);
                } else if (!child.equals(newChild)) {
                    newMp = new MimeMultipart();
                    for (int j = 0; j < i; j++) {
                        newMp.addBodyPart(mp.getBodyPart(j));
                    }
                    newMp.addBodyPart(newChild);
                }
            }
            if (newMp != null) {
                part.setContent(newMp);
            }
            return part;
        } else {
            return part;
        }
    }
}
