package smime;

import jakarta.mail.BodyPart;
import jakarta.mail.MessagingException;
import jakarta.mail.Multipart;
import jakarta.mail.Part;
import jakarta.mail.internet.ContentType;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeUtility;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class PartWalker {

    private final CryptoFactory factory;
    private final PartCallback callback;

    public PartWalker(CryptoFactory factory, PartCallback callback) {
        this.factory = factory;
        this.callback = callback;
    }

    public void walk(MimeMessage message) throws MessagingException, IOException, CryptoException {
        List<SignInfo> noSigners = Collections.emptyList();
        walk(message, noSigners);
    }

    private Crypto getCrypto() {
        return factory.getCrypto();
    }

    private void walkMultipart(Multipart mp, List<SignInfo> signed) throws MessagingException, IOException, CryptoException {
        int count = mp.getCount();
        for (int i = 0; i < count; i++) {
            BodyPart child = mp.getBodyPart(i);
            walk(child, signed);
        }
    }

    private void walk(Part part, List<SignInfo> signed) throws MessagingException, IOException, CryptoException {
        if (part.isMimeType("multipart/signed")) {
            Multipart mp = (Multipart) part.getContent();
            if (mp.getCount() == 2) {
                Part part1 = mp.getBodyPart(0);
                Part part2 = mp.getBodyPart(1);
                Part dataPart;
                Part signaturePart;
                if (part1.isMimeType("application/pkcs7-signature")) {
                    signaturePart = part1;
                    dataPart = part2;
                } else {
                    signaturePart = part2;
                    dataPart = part1;
                }
                List<SignInfo> newSigned = new ArrayList<>(signed);
                try (InputStream is = signaturePart.getInputStream()) {
                    String data = MimeUtil.partToString(dataPart);
                    getCrypto().getSignersDetached(data, is, newSigned);
                }
                walk(dataPart, newSigned);
            } else {
                walkMultipart(mp, signed);
            }
        } else if (part.isMimeType("application/pkcs7-mime")) {
            ContentType contentType = new ContentType(part.getContentType());
            String smime = contentType.getParameter("smime-type");
            List<SignInfo> newSigned;
            String decrypted;
            if ("signed-data".equals(smime)) {
                newSigned = new ArrayList<>(signed);
                try (InputStream is = part.getInputStream()) {
                    decrypted = getCrypto().getSigners(is, newSigned);
                }
            } else {
                newSigned = signed;
                try (InputStream is = part.getInputStream()) {
                    decrypted = getCrypto().decryptData(is);
                }
            }
            walk(new MimeBodyPart(new ByteArrayInputStream(decrypted.getBytes())), newSigned);
        } else if (part.isMimeType("multipart/*")) {
            Multipart mp = (Multipart) part.getContent();
            walkMultipart(mp, signed);
        } else if (part.isMimeType("message/rfc822")) {
            MimeMessage nested = new MimeMessage(null, part.getInputStream());
            walk(nested, signed);
        } else {
            callback.leafPart(part, signed);
        }
    }

    public static String getFileName(Part dataPart) throws MessagingException {
        String fileName = dataPart.getFileName();
        if (fileName == null)
            return null;
        try {
            return MimeUtility.decodeText(fileName);
        } catch (UnsupportedEncodingException ex) {
            return fileName;
        }
    }
}
