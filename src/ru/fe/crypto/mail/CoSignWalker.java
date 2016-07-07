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
        MyBodyPart part = walk(message, signed);
        return new CoSignedMessage(part, signed[0]);
    }

    private Crypto getCrypto() {
        return factory.getCrypto();
    }

    @SuppressWarnings("TailRecursion")
    private MyBodyPart walk(MimePart part, boolean[] signed) throws MessagingException, IOException, CryptoException {
        if (part.isMimeType("multipart/signed")) {
            signed[0] = true;
            return builder.cosignDetached(part, addKey);
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
            ContentType contentType = new ContentType(mp.getContentType());
            MimeMultipart newMp = new MimeMultipart(contentType.getSubType());
            int count = mp.getCount();
            for (int i = 0; i < count; i++) {
                MimeBodyPart child = (MimeBodyPart) mp.getBodyPart(i);
                MyBodyPart newChild = walk(child, signed);
                newMp.addBodyPart(newChild.getPart());
            }
            return MyBodyPart.complex(newMp);
        } else {
            return MyBodyPart.simple(part);
        }
    }
}
