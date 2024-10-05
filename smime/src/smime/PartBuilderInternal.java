package smime;

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

    private static SMimePart createPart(MimePart headers, String base64) throws MessagingException, IOException {
        BiByteArrayStream bis = new BiByteArrayStream();
        MimeUtil.composePart(bis.output(), headers, base64);
        return SMimePart.simple(bis.input());
    }

    private static SMimePart createCryptoPart(String mimeType, String fileName, String base64) throws MessagingException, IOException {
        MimeBodyPart headers = new MimeBodyPart();
        headers.setHeader(CONTENT_TYPE, mimeType);
        headers.setHeader(CONTENT_TRANSFER_ENCODING, BASE64);
        headers.setDisposition(Part.ATTACHMENT);
        headers.setFileName(fileName);
        return createPart(headers, base64);
    }

    private static SMimePart createCryptoPart(String mimeSubType, String base64) throws MessagingException, IOException {
        return createCryptoPart("application/pkcs7-mime; smime-type=\"" + mimeSubType + "\"", "smime.p7m", base64);
    }

    private Crypto getCrypto() {
        return factory.getCrypto();
    }

    final SMimePart encrypt(MimeBodyPart part, EncryptKey key) throws CryptoException, IOException, MessagingException {
        String data = MimeUtil.partToString(part);
        String encryptedData = getCrypto().encryptData(data, key);
        return createCryptoPart("enveloped-data", encryptedData);
    }

    final SMimePart sign(Part part, SignKey key) throws MessagingException, IOException, CryptoException {
        String data = MimeUtil.partToString(part);
        String signedData = getCrypto().signData(data, key, false);
        return createCryptoPart("signed-data", signedData);
    }

    final SMimePart cosign(Part part, SignKey key) throws MessagingException, IOException, CryptoException {
        String cosignedData;
        try (InputStream is = part.getInputStream()) {
            cosignedData = getCrypto().cosignData(null, is, key);
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

    final SMimePart signDetached(BodyPart part, String preamble, SignKey key) throws MessagingException, CryptoException, IOException {
        String data = MimeUtil.partToString(part);
        String signature = getCrypto().signData(data, key, true);
        MimeMultipart mp = createSignedMultipart(part, signature, preamble);
        return SMimePart.complex(mp);
    }

    final SMimePart cosignDetached(Part part, SignKey key) throws MessagingException, IOException, CryptoException {
        MimeMultipart mp = (MimeMultipart) part.getContent();
        if (mp.getCount() == 2) {
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
            String cosigned;
            try (InputStream is = signaturePart.getInputStream()) {
                cosigned = getCrypto().cosignData(data, is, key);
            }
            MimeMultipart newMp = createSignedMultipart(dataPart, cosigned, mp.getPreamble());
            return SMimePart.complex(newMp);
        } else {
            return PartBuilder.fromPart(part);
        }
    }

    public static SMimePart createText(String text, String charset) throws MessagingException, IOException {
        MimeBodyPart part = new MimeBodyPart();
        part.setText(text, charset);
        return SMimePart.simple(part);
    }

    public static SMimePart createFile(InputStreamSource src, PartModifier builder) throws MessagingException, IOException {
        MimeBodyPart headers = new MimeBodyPart();
        headers.setHeader(CONTENT_TRANSFER_ENCODING, BASE64);
        builder.modify(headers);
        String base64;
        try (InputStream is = src.open()) {
            base64 = MimeUtil.base64(is);
        }
        return createPart(headers, base64);
    }

    /**
     * @param encoding null to use RFC2231 encoding;
     *                 "Q" or "B" to encode file name (non-standard)
     */
    public static SMimePart createFileEncoded(InputStreamSource src, String contentType, String charset, String description,
                                              String encoding) throws MessagingException, IOException {
        return createFile(src, headers -> {
            headers.setDescription(description, charset);
            headers.setHeader(CONTENT_TYPE, contentType);
            ContentDisposition disposition = new ContentDisposition(Part.ATTACHMENT);
            ParameterList params = new ParameterList();
            disposition.setParameterList(params);
            String fileName;
            if (encoding == null) {
                fileName = src.getName();
            } else {
                fileName = MimeUtility.encodeText(src.getName(), charset, encoding);
            }
            params.set("filename", fileName, charset);
            headers.setDisposition(disposition.toString());
        });
    }

    public static SMimePart createFile(InputStreamSource src, String contentType, String charset, String description) throws MessagingException, IOException {
        return createFileEncoded(src, contentType, charset, description, null);
    }

    static SMimePart createMulti(String preamble, String mimeSubType, BodyPart... parts) throws MessagingException {
        MimeMultipart mp = new MimeMultipart(mimeSubType);
        mp.setPreamble(preamble);
        for (BodyPart part : parts) {
            mp.addBodyPart(part);
        }
        return SMimePart.complex(mp);
    }
}
