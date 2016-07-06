package ru.fe.crypto.mail;

import com.sun.mail.util.CRLFOutputStream;
import com.sun.mail.util.LineOutputStream;

import javax.mail.*;
import javax.mail.internet.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Enumeration;

public final class PartBuilder {

    private static final String CONTENT_TYPE = "Content-Type";
    private static final String CONTENT_TRANSFER_ENCODING = "Content-Transfer-Encoding";
    private static final String ENVELOPE_FILE = "smime.p7m";
    private static final String SIGNATURE_FILE = "smime.p7s";
    private static final String BASE64 = "base64";

    private final CryptoFactory factory;
    private final String charset;

    public PartBuilder(CryptoFactory factory, String charset) {
        this.factory = factory;
        this.charset = charset;
    }

    private static MimeBodyPart createPart(MimePart headers, String base64) throws MessagingException, IOException {
        BiByteArrayStream bis = new BiByteArrayStream();
        LineOutputStream los = new LineOutputStream(bis.output());
        MimeUtil.writeHeaders(headers, los);
        los.writeln(base64); // todo: remove extra eoln???
        los.flush();
        return new MimeBodyPart(bis.input());
    }

    private static MimeBodyPart createCryptoPart(String smime, String base64) throws MessagingException, IOException {
        MimeBodyPart headers = new MimeBodyPart();
        headers.setHeader(CONTENT_TYPE, "application/pkcs7-mime; smime-type=\"" + smime + "\"");
        headers.setHeader(CONTENT_TRANSFER_ENCODING, BASE64);
        headers.setDisposition(Part.ATTACHMENT);
        headers.setFileName(ENVELOPE_FILE);
        return createPart(headers, base64);
    }

    private Crypto getCrypto() {
        return factory.getCrypto();
    }

    public static void write(Part part, OutputStream os) throws IOException, MessagingException {
        part.writeTo(new CRLFOutputStream(os));
    }

    private static String partToString(Part part) throws IOException, MessagingException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        write(part, bos);
        return bos.toString();
    }

    public MimeBodyPart encrypt(Part part, EncryptKey key) throws CryptoException, IOException, MessagingException {
        String data = partToString(part);
        String encryptedData = getCrypto().encryptData(data, key);
        return createCryptoPart("enveloped-data", encryptedData);
    }

    public MimeBodyPart sign(BodyPart part, SignKey key, boolean detached) throws MessagingException, IOException, CryptoException {
        if (detached) {
            return signDetached(part, key);
        } else {
            return sign(part, key);
        }
    }

    public MimeBodyPart sign(Part part, SignKey key) throws MessagingException, IOException, CryptoException {
        String data = partToString(part);
        String signedData = getCrypto().signData(data, key, false);
        return createCryptoPart("signed-data", signedData);
    }

    public MimeBodyPart cosign(Part part, SignKey key) throws MessagingException, IOException, CryptoException {
        InputStream is = part.getInputStream();
        String cosignedData;
        try {
            cosignedData = getCrypto().cosignData(null, is, key, false);
        } finally {
            MimeUtil.close(is);
        }
        return createCryptoPart("signed-data", cosignedData);
    }

    public MimeBodyPart signDetached(BodyPart part, SignKey key) throws MessagingException, CryptoException, IOException {
        return signDetached(part, "This is an S/MIME multipart signed message", key);
    }

    private static MimeBodyPart createSignaturePart(String signature) throws MessagingException, IOException {
        MimeBodyPart sigHeader = new MimeBodyPart();
        sigHeader.setHeader(CONTENT_TYPE, "application/pkcs7-signature");
        sigHeader.setHeader(CONTENT_TRANSFER_ENCODING, BASE64);
        sigHeader.setDisposition(Part.ATTACHMENT);
        sigHeader.setFileName(SIGNATURE_FILE);
        return createPart(sigHeader, signature);
    }

    private static MimeMultipart createSignedMultipart(BodyPart dataPart, String signature, String preamble) throws MessagingException, IOException {
        MimeMultipart mp = new MimeMultipart("signed; protocol=\"application/pkcs7-signature\"");
        if (preamble != null) {
            mp.setPreamble(preamble);
        }
        mp.addBodyPart(dataPart);
        mp.addBodyPart(createSignaturePart(signature));
        return mp;
    }

    public MimeBodyPart signDetached(BodyPart part, String preamble, SignKey key) throws MessagingException, CryptoException, IOException {
        String data = partToString(part);
        String signature = getCrypto().signData(data, key, true);
        MimeMultipart mp = createSignedMultipart(part, signature, preamble);
        MimeBodyPart complexPart = new MimeBodyPart();
        complexPart.setContent(mp);
        complexPart.setHeader(CONTENT_TYPE, "multipart/signed; protocol=\"application/pkcs7-signature\"");
        return complexPart;
    }

    public void cosignDetached(Part part, SignKey key) throws MessagingException, IOException, CryptoException {
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
        String data = partToString(dataPart);
        InputStream is = signaturePart.getInputStream();
        String cosigned;
        try {
            cosigned = getCrypto().cosignData(data, is, key, true);
        } finally {
            MimeUtil.close(is);
        }
        MimeMultipart newMp = createSignedMultipart(dataPart, cosigned, mp.getPreamble());
        part.setContent(newMp);
    }

    public MimeBodyPart createText(String text) throws MessagingException {
        MimeBodyPart part = new MimeBodyPart();
        part.setHeader(CONTENT_TYPE, "text/plain");
        part.setText(text, charset);
        return part;
    }

    public static MimeBodyPart createMulti(BodyPart... parts) throws MessagingException {
        return createMulti(null, parts);
    }

    public static MimeBodyPart createMulti(String preamble, BodyPart... parts) throws MessagingException {
        MimeBodyPart complexPart = new MimeBodyPart();
        MimeMultipart mp = new MimeMultipart();
        if (preamble != null) {
            mp.setPreamble(preamble);
        }
        for (BodyPart part : parts) {
            mp.addBodyPart(part);
        }
        complexPart.setContent(mp);
        return complexPart;
    }

    public MimeBodyPart createFile(InputStreamSource src, String contentType, String comment) throws MessagingException, IOException {
        MimeBodyPart filePart = new MimeBodyPart();
        String headers = src.getName();
        filePart.setDescription(comment);
        filePart.setHeader(CONTENT_TYPE, contentType);
        filePart.setHeader(CONTENT_TRANSFER_ENCODING, BASE64);
        ContentDisposition disposition = new ContentDisposition(Part.ATTACHMENT);
        disposition.setParameter("filename", MimeUtility.encodeText(headers, charset, "Q"));
        filePart.setDisposition(disposition.toString());
        String base64 = Base64.base64(src.open());
        return createPart(filePart, base64);
    }

    private static MimeMessage writeMessage(Session session, MimeMessage message, InputStream data) throws MessagingException, IOException {
        BiByteArrayStream bis = new BiByteArrayStream();
        LineOutputStream los = new LineOutputStream(bis.output());
        MimeUtil.writeHeaders(message, los);
        MimeUtil.copyStreamEoln(data, los);
        los.flush();
        return new MimeMessage(session, bis.input());
    }

    public static MimeMessage toMessage(Session session, MimeBodyPart part) throws MessagingException, IOException {
        MimeMessage message = new MimeMessage(session);

        Object content = part.getContent();
        if (content instanceof Multipart) {
            Multipart mp = (Multipart) content;
            message.setContent(mp);
            message.saveChanges();
            return message;
        } else {
            message.saveChanges();
            Enumeration<?> headers = part.getAllHeaderLines();
            while (headers.hasMoreElements()) {
                String line = (String) headers.nextElement();
                message.addHeaderLine(line);
            }
            InputStream is = part.getRawInputStream();
            try {
                return writeMessage(session, message, is);
            } finally {
                MimeUtil.close(is);
            }
        }
    }
}
