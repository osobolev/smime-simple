package ru.fe.crypto.mail;

import ru.fe.common.StreamUtils;

import javax.mail.BodyPart;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.Part;
import javax.mail.internet.ContentType;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimePart;
import java.io.*;
import java.util.ArrayList;
import java.util.List;

final class MailReader {

    private static final String MULTIPART_SIGNED = "multipart/signed";

    private static final class Environment {

        private final CryptoFactory factory;
        private Crypto instance = null;

        private final MimeMessage msg;
        private final boolean needRaw;
        private final List<SignInfo> certificates = new ArrayList<SignInfo>();

        private Environment(CryptoFactory factory, MimeMessage msg, boolean needRaw) {
            this.factory = factory;
            this.msg = msg;
            this.needRaw = needRaw;
        }

        SignedPart decrypt() throws MessagingException, IOException, CryptoException {
            if (msg.isMimeType(MULTIPART_SIGNED)) {
                Multipart parts = (Multipart) msg.getContent();
                return signOnly(parts);
            } else {
                return encSign();
            }
        }

        private Crypto getInstance() {
            if (instance == null) {
                instance = factory.getCrypto();
            }
            return instance;
        }

        private SignedPart encSign() throws MessagingException, IOException, CryptoException {
            MimePart current = msg;
            String rawData = null;
            while (true) {
                if (current.isMimeType("application/pkcs7-mime")) {
                    ContentType contentType = new ContentType(current.getContentType());
                    String smime = contentType.getParameter("smime-type");
                    String partData = MimeUtil.base64(current.getInputStream());
                    String result;
                    Crypto instance = getInstance();
                    if ("signed-data".equals(smime)) {
                        Crypto.SignerData sd = instance.getSigners(partData);
                        if (needRaw) {
                            rawData = partData;
                        }

                        certificates.addAll(sd.signers);
                        result = sd.data;
                    } else {
                        result = instance.decryptData(partData);
                    }
                    current = new MimeBodyPart(new ByteArrayInputStream(result.getBytes()));
                    if (current.isMimeType(MULTIPART_SIGNED)) {
                        Multipart mp = (Multipart) current.getContent();
                        return signOnly(mp);
                    }
                } else {
                    Part attachment = searchAttachment(current);
                    if (attachment == null) {
                        attachment = current;
                    }
                    return new SignedPart(msg, attachment, certificates, rawData, null);
                }
            }
        }

        private static Part searchAttachment(Part part) throws MessagingException, IOException {
            if (part.getFileName() != null) {
                return part;
            }
            if (part.isMimeType("multipart/*")) {
                Multipart mp = (Multipart) part.getContent();
                int count = mp.getCount();
                for (int i = 0; i < count; i++) {
                    BodyPart child = mp.getBodyPart(i);
                    Part found = searchAttachment(child);
                    if (found != null)
                        return found;
                }
            }
            return null;
        }

        private SignedPart signOnly(Multipart parts) throws MessagingException, IOException, CryptoException {
            MimeBodyPart part1 = (MimeBodyPart) parts.getBodyPart(0);
            MimeBodyPart part2 = (MimeBodyPart) parts.getBodyPart(1);
            MimeBodyPart dataPart;
            MimeBodyPart signaturePart;
            if (part1.isMimeType("application/pkcs7-signature")) {
                signaturePart = part1;
                dataPart = part2;
            } else {
                signaturePart = part2;
                dataPart = part1;
            }

            String signatureData = MimeUtil.base64(signaturePart.getInputStream());
            Crypto instance = getInstance();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            write(dataPart, bos);
            String partString = bos.toString();
            List<SignInfo> signatures = instance.getSignersDetached(partString, signatureData);
            if (signatures == null) {
                return new SignedPart(msg, dataPart, new SignInfo[0], null, null, null); // todo: signal signature check error to caller
            }

            certificates.addAll(signatures);

            Part attachmentPart = searchAttachment(dataPart);
            if (attachmentPart == null) {
                attachmentPart = dataPart;
            }
            if (needRaw) {
                return new SignedPart(msg, attachmentPart, certificates, partString, signatureData);
            } else {
                return new SignedPart(msg, attachmentPart, certificates, null, null);
            }
        }

        private static void write(MimeBodyPart part, OutputStream os) throws MessagingException, IOException {
            MimeUtil.writeHeaders(part, os);
            InputStream is = part.getRawInputStream();
            StreamUtils.copyStreamEoln(is, os);
            os.flush();
        }

        void release() {
            instance = null;
        }
    }

    static SignedPart decrypt(CryptoFactory factory, MimeMessage msg, boolean needRaw) throws MessagingException, IOException, CryptoException {
        Environment environment = new Environment(factory, msg, needRaw);
        try {
            return environment.decrypt();
        } finally {
            environment.release();
        }
    }
}
