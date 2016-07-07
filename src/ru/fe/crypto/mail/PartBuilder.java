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
    private static final String BASE64 = "base64";

    private final CryptoFactory factory;

    public PartBuilder(CryptoFactory factory) {
        this.factory = factory;
    }

    private static MyBodyPart createPart(MimePart headers, String base64) throws MessagingException, IOException {
        BiByteArrayStream bis = new BiByteArrayStream();
        LineOutputStream los = new LineOutputStream(bis.output());
        MimeUtil.writeHeaders(headers, los);
        los.writeln(base64); // todo: remove extra eoln???
        los.flush();
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

    public static void write(Part part, OutputStream os) throws IOException, MessagingException {
        part.writeTo(new CRLFOutputStream(os));
    }

    static String partToString(Part part) throws IOException, MessagingException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        write(part, bos);
        return bos.toString();
    }

    public MyBodyPart encrypt(MimeBodyPart part, EncryptKey key) throws CryptoException, IOException, MessagingException {
        String data = partToString(part);
        String encryptedData = getCrypto().encryptData(data, key);
        return createCryptoPart("enveloped-data", encryptedData);
    }

    public MyBodyPart sign(BodyPart part, SignKey key, boolean detached) throws MessagingException, IOException, CryptoException {
        if (detached) {
            return signDetached(part, key);
        } else {
            return sign(part, key);
        }
    }

    public MyBodyPart sign(Part part, SignKey key) throws MessagingException, IOException, CryptoException {
        String data = partToString(part);
        String signedData = getCrypto().signData(data, key, false);
        return createCryptoPart("signed-data", signedData);
    }

    public MyBodyPart cosign(Part part, SignKey key) throws MessagingException, IOException, CryptoException {
        InputStream is = part.getInputStream();
        String cosignedData;
        try {
            cosignedData = getCrypto().cosignData(null, is, key, false);
        } finally {
            MimeUtil.close(is);
        }
        return createCryptoPart("signed-data", cosignedData);
    }

    public MyBodyPart signDetached(BodyPart part, SignKey key) throws MessagingException, CryptoException, IOException {
        return signDetached(part, "This is an S/MIME multipart signed message", key);
    }

    private static MimeMultipart createSignedMultipart(BodyPart dataPart, String signature, String preamble) throws MessagingException, IOException {
        MimeMultipart mp = new MimeMultipart("signed; protocol=\"application/pkcs7-signature\"");
        mp.setPreamble(preamble);
        mp.addBodyPart(dataPart);
        mp.addBodyPart(createCryptoPart("application/pkcs7-signature", "smime.p7s", signature).getPart());
        return mp;
    }

    public MyBodyPart signDetached(BodyPart part, String preamble, SignKey key) throws MessagingException, CryptoException, IOException {
        String data = partToString(part);
        String signature = getCrypto().signData(data, key, true);
        MimeMultipart mp = createSignedMultipart(part, signature, preamble);
        return MyBodyPart.complex(mp);
    }

    public MyBodyPart cosignDetached(Part part, SignKey key) throws MessagingException, IOException, CryptoException {
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
        String data = partToString(dataPart);
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

    public static MyBodyPart createMulti(BodyPart... parts) throws MessagingException {
        return createMulti(null, parts);
    }

    public static MyBodyPart createMulti(String preamble, BodyPart... parts) throws MessagingException {
        MimeMultipart mp = new MimeMultipart(); // todo: add subtype parameter???
        mp.setPreamble(preamble);
        for (BodyPart part : parts) {
            mp.addBodyPart(part);
        }
        return MyBodyPart.complex(mp);
    }

    public static MyBodyPart createFile(InputStreamSource src, String contentType, String charset, String comment) throws MessagingException, IOException {
        MimeBodyPart headers = new MimeBodyPart();
        String fileName = src.getName();
        headers.setDescription(comment);
        headers.setHeader(CONTENT_TYPE, contentType);
        headers.setHeader(CONTENT_TRANSFER_ENCODING, BASE64);
        ContentDisposition disposition = new ContentDisposition(Part.ATTACHMENT);
        disposition.setParameter("filename", MimeUtility.encodeText(fileName, charset, "Q"));
        headers.setDisposition(disposition.toString());
        String base64 = Base64.base64(src.open());
        return createPart(headers, base64);
    }

    private static MimeMessage writeMessage(Session session, MimeMessage message, InputStream data) throws MessagingException, IOException {
        BiByteArrayStream bis = new BiByteArrayStream();
        LineOutputStream los = new LineOutputStream(bis.output());
        MimeUtil.writeHeaders(message, los);
        MimeUtil.copyStreamEoln(data, los);
        los.flush();
        return new MimeMessage(session, bis.input());
    }

    public static MimeMessage toMessage(Session session, MyBodyPart myPart) throws MessagingException, IOException {
        MimeMessage message = new MimeMessage(session);

        MimeBodyPart part = myPart.getPart();
        Object content = part.getContent();
        MimeMessage result;
        if (content instanceof Multipart) {
            Multipart mp = (Multipart) content;
            message.setContent(mp);
            result = message;
        } else {
            message.saveChanges();
            Enumeration<?> headers = part.getAllHeaderLines();
            while (headers.hasMoreElements()) {
                String line = (String) headers.nextElement();
                message.addHeaderLine(line);
            }
            InputStream is = part.getRawInputStream();
            try {
                result = writeMessage(session, message, is);
            } finally {
                MimeUtil.close(is);
            }
        }
        result.saveChanges();
        return result;
    }
}
