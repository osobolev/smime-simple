package ru.fe.crypto.mail;

import ru.fe.common.StreamUtils;

import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.internet.*;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public final class CoSignWalker {

    private final CryptoFactory factory;
    private final SignKey addKey;

    public CoSignWalker(CryptoFactory factory, SignKey addKey) {
        this.factory = factory;
        this.addKey = addKey;
    }

    void walk(MimeMessage message) throws MessagingException, IOException, CryptoException {
        walk((MimePart) message);
    }

    private Crypto getCrypto() {
        return factory.getCrypto();
    }

    // todo: dup code
    private static InputStream canonicalize(MimeBodyPart part) throws MessagingException, IOException {
        BiByteArrayStream bis = new BiByteArrayStream();
        MimeUtil.writeHeaders(part, bis.output());
        InputStream is = part.getRawInputStream(); // todo: why???
        StreamUtils.copyStreamEoln(is, bis.output());
        return bis.input();
    }

    MimePart walk(MimePart part) throws MessagingException, IOException, CryptoException {
        if (part.isMimeType("multipart/signed")) {
            Multipart mp = (Multipart) part.getContent();
            MimeBodyPart part1 = (MimeBodyPart) mp.getBodyPart(0);
            MimeBodyPart part2 = (MimeBodyPart) mp.getBodyPart(1);
            MimeBodyPart dataPart;
            MimeBodyPart signaturePart;
            if (part1.isMimeType("application/pkcs7-signature")) {
                signaturePart = part1;
                dataPart = part2;
            } else {
                signaturePart = part2;
                dataPart = part1;
            }
            InputStream data = canonicalize(dataPart);
            String cosigned = getCrypto().cosignData(null, null, addKey, true); // todo
            MimeMultipart newMp = new MimeMultipart();
            newMp.addBodyPart(dataPart);
            // todo: add new signed part
            part.setContent(newMp);
            return part;
        } else if (part.isMimeType("application/pkcs7-mime")) {
            ContentType contentType = new ContentType(part.getContentType());
            String smime = contentType.getParameter("smime-type");
            if ("signed-data".equals(smime)) {
                String cosigned = getCrypto().cosignData(null, null, addKey, false); // todo
                // todo: rebuild new part with new signature!
                return part;
            } else {
                String decrypted = getCrypto().decryptData(part.getInputStream());
                // todo: remove old encryption, add new if necessary (bc this is a message for new receiver with new key)
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
