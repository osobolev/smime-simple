package ru.fe.crypto.mail;

import javax.mail.BodyPart;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.Part;
import javax.mail.internet.ContentType;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
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

    private static InputStream canonicalize(Part part) throws MessagingException, IOException {
        BiByteArrayStream bis = new BiByteArrayStream();
        PartBuilder.write(part, bis.output());
        return bis.input();
    }

    private void walk(Part part, List<SignInfo> signed) throws MessagingException, IOException, CryptoException {
        if (part.isMimeType("multipart/signed")) {
            Multipart mp = (Multipart) part.getContent();
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
            List<SignInfo> newSigned = new ArrayList<SignInfo>(signed);
            InputStream is = signaturePart.getInputStream();
            List<SignInfo> signers;
            try {
                InputStream data = canonicalize(dataPart);
                signers = getCrypto().getSignersDetached(data, is);
            } finally {
                MimeUtil.close(is);
            }
            newSigned.addAll(signers);
            walk(dataPart, newSigned);
        } else if (part.isMimeType("application/pkcs7-mime")) {
            ContentType contentType = new ContentType(part.getContentType());
            String smime = contentType.getParameter("smime-type");
            List<SignInfo> newSigned;
            String decrypted;
            if ("signed-data".equals(smime)) {
                InputStream is = part.getInputStream();
                Crypto.SignerData sd;
                try {
                    sd = getCrypto().getSigners(is);
                } finally {
                    MimeUtil.close(is);
                }
                newSigned = new ArrayList<SignInfo>(signed);
                newSigned.addAll(sd.signers);
                decrypted = sd.data;
            } else {
                newSigned = signed;
                InputStream is = part.getInputStream();
                try {
                    decrypted = getCrypto().decryptData(is);
                } finally {
                    MimeUtil.close(is);
                }
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
