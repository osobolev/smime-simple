package ru.fe.crypto.mail;

import ru.fe.common.StreamUtils;

import javax.mail.BodyPart;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.Part;
import javax.mail.internet.ContentType;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import java.io.*;
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

    void walk(MimeMessage message) throws MessagingException, IOException, CryptoException {
        List<SignInfo> noSigners = Collections.emptyList();
        walk(message, noSigners);
    }

    private Crypto getCrypto() {
        return factory.getCrypto();
    }

    private static InputStream canonicalize(MimeBodyPart part) throws MessagingException, IOException {
        BiByteArrayStream bis = new BiByteArrayStream();
        MimeUtil.writeHeaders(part, bis.output());
        InputStream is = part.getRawInputStream(); // todo: why???
        StreamUtils.copyStreamEoln(is, bis.output());
        return bis.input();
    }

    void walk(Part part, List<SignInfo> signed) throws MessagingException, IOException, CryptoException {
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
            List<SignInfo> newSigned = new ArrayList<SignInfo>(signed);
            List<SignInfo> signers = getCrypto().getSignersDetached(data, signaturePart.getInputStream());
            newSigned.addAll(signers);
            walk(dataPart, newSigned);
        } else if (part.isMimeType("application/pkcs7-mime")) {
            ContentType contentType = new ContentType(part.getContentType());
            String smime = contentType.getParameter("smime-type");
            List<SignInfo> newSigned;
            String decrypted;
            if ("signed-data".equals(smime)) {
                Crypto.SignerData sd = getCrypto().getSigners(part.getInputStream());
                newSigned = new ArrayList<SignInfo>(signed);
                newSigned.addAll(sd.signers);
                decrypted = sd.data;
            } else {
                newSigned = signed;
                decrypted = getCrypto().decryptData(part.getInputStream());
            }
            walk(new MimeBodyPart(new ByteArrayInputStream(decrypted.getBytes())), newSigned);
        } else if (part.isMimeType("multipart/*")) {
            Multipart mp = (Multipart) part.getContent();
            int count = mp.getCount();
            for (int i = 0; i < count; i++) {
                BodyPart child = mp.getBodyPart(i);
                walk(child, signed);
            }
        } else {
            callback.leafPart(part, signed);
        }
    }
}
