package ru.fe.crypto.mail;

import javax.mail.BodyPart;
import javax.mail.MessagingException;
import javax.mail.Part;
import javax.mail.internet.*;
import java.io.IOException;
import java.io.InputStream;

class PartBuilderInternal {

    private static final String CONTENT_TYPE = "Content-Type";
    private static final String CONTENT_TRANSFER_ENCODING = "Content-Transfer-Encoding";
    private static final String BASE64 = "base64";

    private final CryptoFactory factory;

    PartBuilderInternal(CryptoFactory factory) {
        this.factory = factory;
    }

    private static MyBodyPart createPart(MimePart headers, String base64) throws MessagingException, IOException {
        BiByteArrayStream bis = new BiByteArrayStream();
        MimeUtil.composePart(bis.output(), headers, base64);
        return MyBodyPart.simple(bis.input());
    }

    private static MyBodyPart createCryptoPart(String mimeType, String fileName, String base64) throws MessagingException, IOException {
        MimeBodyPart headers = new MimeBodyPart();
        headers.setHeader(CONTENT_TYPE, mimeType);
        headers.setHeader(CONTENT_TRANSFER_ENCODING, BASE64);
        headers.setDisposition(Part.ATTACHMENT);
        headers.setFileName(fileName);
        return createPart(headers, base64);
    }

    private static MyBodyPart createCryptoPart(String mimeSubType, String base64) throws MessagingException, IOException {
        return createCryptoPart("application/pkcs7-mime; smime-type=\"" + mimeSubType + "\"", "smime.p7m", base64);
    }

    private Crypto getCrypto() {
        return factory.getCrypto();
    }

    final MyBodyPart encrypt(MimeBodyPart part, EncryptKey key) throws CryptoException, IOException, MessagingException {
        String data = MimeUtil.partToString(part);
        String encryptedData = getCrypto().encryptData(data, key);
        return createCryptoPart("enveloped-data", encryptedData);
    }

    final MyBodyPart sign(Part part, SignKey key) throws MessagingException, IOException, CryptoException {
        String data = MimeUtil.partToString(part);
        String signedData = getCrypto().signData(data, key, false);
        return createCryptoPart("signed-data", signedData);
    }

    final MyBodyPart cosign(Part part, SignKey key) throws MessagingException, IOException, CryptoException {
        InputStream is = part.getInputStream();
        String cosignedData;
        try {
            cosignedData = getCrypto().cosignData(null, is, key, false);
        } finally {
            MimeUtil.close(is);
        }
        return createCryptoPart("signed-data", cosignedData);
    }

    private static MimeMultipart createSignedMultipart(BodyPart dataPart, String signature, String preamble) throws MessagingException, IOException {
        MimeMultipart mp = new MimeMultipart("signed; protocol=\"application/pkcs7-signature\"");
        mp.setPreamble(preamble);
        mp.addBodyPart(dataPart);
        mp.addBodyPart(createCryptoPart("application/pkcs7-signature", "smime.p7s", signature).getPart());
        return mp;
    }

    final MyBodyPart signDetached(BodyPart part, String preamble, SignKey key) throws MessagingException, CryptoException, IOException {
        String data = MimeUtil.partToString(part);
        String signature = getCrypto().signData(data, key, true);
        MimeMultipart mp = createSignedMultipart(part, signature, preamble);
        return MyBodyPart.complex(mp);
    }

    final MyBodyPart cosignDetached(Part part, SignKey key) throws MessagingException, IOException, CryptoException {
        MimeMultipart mp = (MimeMultipart) part.getContent();
        BodyPart part1 = mp.getBodyPart(0);
        BodyPart part2 = mp.getBodyPart(1);
        BodyPart dataPart;
        BodyPart signaturePart;
        if (part1.isMimeType("application/pkcs7-signature")) {
            signaturePart = part1;
            dataPart = part2;
        } else {
            signaturePart = part2;
            dataPart = part1;
        }
        String data = MimeUtil.partToString(dataPart);
        InputStream is = signaturePart.getInputStream();
        String cosigned;
        try {
            cosigned = getCrypto().cosignData(data, is, key, true);
        } finally {
            MimeUtil.close(is);
        }
        MimeMultipart newMp = createSignedMultipart(dataPart, cosigned, mp.getPreamble());
        return MyBodyPart.complex(newMp);
    }

    public static MyBodyPart createText(String text, String charset) throws MessagingException, IOException {
        MimeBodyPart part = new MimeBodyPart();
        part.setText(text, charset);
        return MyBodyPart.simple(part);
    }

    public static MyBodyPart createFile(InputStreamSource src, String contentType, String charset, String comment) throws MessagingException, IOException {
        MimeBodyPart headers = new MimeBodyPart();
        headers.setDescription(comment);
        headers.setHeader(CONTENT_TYPE, contentType);
        headers.setHeader(CONTENT_TRANSFER_ENCODING, BASE64);
        ContentDisposition disposition = new ContentDisposition(Part.ATTACHMENT);
        disposition.setParameter("filename", MimeUtility.encodeText(src.getName(), charset, "Q"));
        headers.setDisposition(disposition.toString());
        String base64 = MimeUtil.base64(src.open());
        return createPart(headers, base64);
    }

    static MyBodyPart createMulti(String preamble, String mimeSubType, BodyPart... parts) throws MessagingException {
        MimeMultipart mp = new MimeMultipart(mimeSubType);
        mp.setPreamble(preamble);
        for (BodyPart part : parts) {
            mp.addBodyPart(part);
        }
        return MyBodyPart.complex(mp);
    }
}
