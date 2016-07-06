package ru.fe.crypto.mail;

import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.Session;
import javax.mail.internet.*;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;

public final class CoSignWalker {

    private final CryptoFactory factory;
    private final PartBuilder builder;
    private final SignKey addKey;
    // todo: add detached flag???

    public CoSignWalker(CryptoFactory factory, SignKey addKey) {
        this.factory = factory;
        this.builder = new PartBuilder(factory, "Windows-1251"); // todo: param
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
        return cosigned;
    }

    private Crypto getCrypto() {
        return factory.getCrypto();
    }

    // todo: dup code
    private static String canonicalize(MimeBodyPart part) throws MessagingException, IOException {
        // todo: why not part.writeTo???
        BiByteArrayStream bis = new BiByteArrayStream();
        MimeUtil.writeHeaders(part, bis.output());
        InputStream is = part.getRawInputStream(); // todo: why???
        try {
            MimeUtil.copyStreamEoln(is, bis.output());
        } finally {
            MimeUtil.close(is);
        }
        return bis.toString();
    }

    private static void add(ParameterList params, ContentType type) {
        ParameterList list = type.getParameterList();
        Enumeration<?> names = list.getNames();
        while (names.hasMoreElements()) {
            String name = (String) names.nextElement();
            String value = list.get(name);
            params.set(name, value);
        }
    }

    private MimePart walk(MimePart part) throws MessagingException, IOException, CryptoException {
        if (part.isMimeType("multipart/signed")) {
            ContentType oldContentType = new ContentType(part.getContentType());
            MimeMultipart mp = (MimeMultipart) part.getContent();
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
            String data = canonicalize(dataPart);
            InputStream is = signaturePart.getInputStream();
            String cosigned;
            try {
                cosigned = getCrypto().cosignData(data, is, addKey, true);
            } finally {
                MimeUtil.close(is);
            }
            MimeMultipart newMp = new MimeMultipart(); // todo: reuse PartBuilder code???
            // todo: set preamble
            newMp.addBodyPart(dataPart);
            MimeBodyPart newSignPart = PartBuilder.createSignaturePart(cosigned);
            newMp.addBodyPart(newSignPart);
            part.setContent(newMp);
            ContentType mpContentType = new ContentType(newMp.getContentType());
            ParameterList params = new ParameterList();
            add(params, oldContentType);
            add(params, mpContentType);
            ContentType newContentType = new ContentType(oldContentType.getPrimaryType(), oldContentType.getSubType(), mpContentType.getParameterList());
            part.setHeader("Content-Type", newContentType.toString());
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
