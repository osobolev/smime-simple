package ru.fe.crypto.mail;

import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.internet.*;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public final class CoSignWalker {

    private final CryptoFactory factory;
    private final PartBuilder builder;
    private final SignKey addKey;

    public CoSignWalker(CryptoFactory factory, SignKey addKey) {
        this.factory = factory;
        this.builder = new PartBuilder(factory);
        this.addKey = addKey;
    }

    public CoSignedMessage walk(MimeMessage message) throws MessagingException, IOException, CryptoException {
        boolean[] signed = new boolean[1];
        MimePart part = walk(message, signed);
        if (part instanceof MimeBodyPart) {
            MimeBodyPart mbp = (MimeBodyPart) part;
            return new CoSignedMessage(null, mbp, signed[0]);
        } else {
            message.saveChanges();
            return new CoSignedMessage(message, null, signed[0]);
        }
    }

    private Crypto getCrypto() {
        return factory.getCrypto();
    }

    @SuppressWarnings("TailRecursion")
    private MimePart walk(MimePart part, boolean[] signed) throws MessagingException, IOException, CryptoException {
        if (part.isMimeType("multipart/signed")) {
            signed[0] = true;
            builder.cosignDetached(part, addKey);
            return part;
        } else if (part.isMimeType("application/pkcs7-mime")) {
            ContentType contentType = new ContentType(part.getContentType());
            String smime = contentType.getParameter("smime-type");
            if ("signed-data".equals(smime)) {
                signed[0] = true;
                return builder.cosign(part, addKey);
            } else {
                InputStream is = part.getInputStream();
                String decrypted;
                try {
                    decrypted = getCrypto().decryptData(is);
                } finally {
                    MimeUtil.close(is);
                }
                return walk(new MimeBodyPart(new ByteArrayInputStream(decrypted.getBytes())), signed);
            }
        } else if (part.isMimeType("multipart/*")) {
            Multipart mp = (Multipart) part.getContent();
            MimeMultipart newMp = null;
            int count = mp.getCount();
            for (int i = 0; i < count; i++) {
                MimeBodyPart child = (MimeBodyPart) mp.getBodyPart(i);
                MimeBodyPart newChild = (MimeBodyPart) walk(child, signed);
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
