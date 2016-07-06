package ru.fe.crypto.mail;

import com.sun.mail.util.LineOutputStream;
import ru.fe.common.StreamUtils;

import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.Part;
import javax.mail.Session;
import javax.mail.internet.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
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

    private static void writeMessage(OutputStream os, MimePart headers, String base64) throws MessagingException, IOException {
        LineOutputStream los = MimeUtil.toLOS(os);
        MimeUtil.writeHeaders(headers, los);
        los.writeln(base64); // todo: remove extra eoln???
        los.flush();
    }

    private static MimeBodyPart createPart(String base64, String smime) throws MessagingException, IOException {
        MimeBodyPart headers = new MimeBodyPart();
        headers.setHeader(CONTENT_TYPE, "application/pkcs7-mime; smime-type=\"" + smime + "\"");
        headers.setHeader(CONTENT_TRANSFER_ENCODING, BASE64);
        headers.setDisposition(Part.ATTACHMENT);
        headers.setFileName(ENVELOPE_FILE);
        BiByteArrayStream bis = new BiByteArrayStream();
        writeMessage(bis.output(), headers, base64);
        return new MimeBodyPart(bis.input());
    }

    private Crypto getCrypto() {
        return factory.getCrypto();
    }

    private static String partToString(Part part) throws IOException, MessagingException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        SignedPart.write(part, bos);
        return bos.toString();
    }

    public MimeBodyPart encrypt(Part part, EncryptKey key) throws CryptoException, IOException, MessagingException {
        String data = partToString(part);
        String encryptedData = getCrypto().encryptData(data, key);
        return createPart(encryptedData, "enveloped-data");
    }

    public MimeBodyPart sign(Part part, SignKey key) throws MessagingException, IOException, CryptoException {
        String data = partToString(part);
        String signedData = getCrypto().signData(data, key, false);
        return createPart(signedData, "signed-data");
    }

    public MimeBodyPart signDetached(Part part, SignKey key) throws MessagingException, CryptoException, IOException {
        return signDetached(part, "This is an S/MIME multipart signed message", key);
    }

    public MimeBodyPart signDetached(Part part, String preamble, SignKey key) throws MessagingException, CryptoException, IOException {
        MimeBodyPart complexPart = new MimeBodyPart();
        MimeMultipart mp = new MimeMultipart("signed; protocol=\"application/pkcs7-signature\"");
        if (preamble != null) {
            mp.setPreamble(preamble);
        }
        String data = partToString(part);
        MimeBodyPart dataPart;
        {
            dataPart = new MimeBodyPart(new ByteArrayInputStream(data.getBytes())); // todo: optimize
        }
        mp.addBodyPart(dataPart);
        MimeBodyPart signaturePart;
        {
            String signature = getCrypto().signData(data, key, true);
            MimeBodyPart sigHeader = new MimeBodyPart();
            sigHeader.setHeader(CONTENT_TYPE, "application/pkcs7-signature");
            sigHeader.setHeader(CONTENT_TRANSFER_ENCODING, BASE64);
            sigHeader.setDisposition(Part.ATTACHMENT);
            sigHeader.setFileName(SIGNATURE_FILE);
            BiByteArrayStream bis = new BiByteArrayStream();
            writeMessage(bis.output(), sigHeader, signature);
            signaturePart = new MimeBodyPart(bis.input());
        }
        mp.addBodyPart(signaturePart);
        complexPart.setContent(mp);
        complexPart.setHeader(CONTENT_TYPE, "multipart/signed; protocol=\"application/pkcs7-signature\"");
        return complexPart;
    }

    public MimeBodyPart create(InputStreamSource src, String contentType, String comment) throws MessagingException, IOException {
        MimeBodyPart filePart = new MimeBodyPart();
        String headers = src.getName();
        filePart.setDescription(comment);
        filePart.setHeader(CONTENT_TYPE, contentType);
        filePart.setHeader(CONTENT_TRANSFER_ENCODING, BASE64);
        ContentDisposition disposition = new ContentDisposition(Part.ATTACHMENT);
        disposition.setParameter("filename", MimeUtility.encodeText(headers, charset, "Q"));
        filePart.setDisposition(disposition.toString());
        BiByteArrayStream bis = new BiByteArrayStream();
        String base64 = MimeUtil.base64(src.open());
        writeMessage(bis.output(), filePart, base64);
        return new MimeBodyPart(bis.input());
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
            String raw = new String(StreamUtils.toByteArray(part.getRawInputStream())); // todo: optimize further???
//          raw = MimeUtil.base64(part.getInputStream()); // todo: ???
            BiByteArrayStream bis = new BiByteArrayStream();
            writeMessage(bis.output(), message, raw);
            return new MimeMessage(session, bis.input());
        }
    }
}
