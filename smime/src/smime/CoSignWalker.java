package smime;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.*;

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
        SMimePart part = walk(message, signed);
        return new CoSignedMessage(part, signed[0]);
    }

    private Crypto getCrypto() {
        return factory.getCrypto();
    }

    @SuppressWarnings("TailRecursion")
    private SMimePart walk(MimePart part, boolean[] signed) throws MessagingException, IOException, CryptoException {
        if (part.isMimeType("multipart/signed")) {
            signed[0] = true;
            if (addKey == null) {
                return PartBuilder.fromPart(part);
            } else {
                return builder.cosignDetached(part, addKey);
            }
        } else if (part.isMimeType("application/pkcs7-mime")) {
            ContentType contentType = new ContentType(part.getContentType());
            String smime = contentType.getParameter("smime-type");
            if ("signed-data".equals(smime)) {
                signed[0] = true;
                if (addKey == null) {
                    return PartBuilder.fromPart(part);
                } else {
                    return builder.cosign(part, addKey);
                }
            } else {
                String decrypted;
                try (InputStream is = part.getInputStream()) {
                    decrypted = getCrypto().decryptData(is);
                }
                return walk(new MimeBodyPart(new ByteArrayInputStream(decrypted.getBytes())), signed);
            }
        } else if (part.isMimeType("multipart/*")) {
            MimeMultipart mp = (MimeMultipart) part.getContent();
            String contentType = mp.getContentType();
            int p = contentType.indexOf('/');
            MimeMultipart newMp;
            if (p >= 0) {
                newMp = new MimeMultipart(contentType.substring(p + 1));
            } else {
                newMp = new MimeMultipart();
            }
            newMp.setPreamble(mp.getPreamble());
            int count = mp.getCount();
            for (int i = 0; i < count; i++) {
                MimeBodyPart child = (MimeBodyPart) mp.getBodyPart(i);
                SMimePart newChild = walk(child, signed);
                newMp.addBodyPart(newChild.getPart());
            }
            return SMimePart.complex(newMp);
        } else {
            return PartBuilder.fromPart(part);
        }
    }
}
