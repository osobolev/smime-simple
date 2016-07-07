package ru.fe.crypto.mail;

import com.sun.mail.util.LineOutputStream;

import javax.mail.MessagingException;
import javax.mail.Part;
import javax.mail.Session;
import javax.mail.internet.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

final class MailWriter {

    private static final String CONTENT_TYPE = "Content-Type";
    private static final String CONTENT_TRANSFER_ENCODING = "Content-Transfer-Encoding";

    private static final String ENVELOPE_FILE = "smime.p7m";
    private static final String SIGNATURE_FILE = "smime.p7s";
    private static final String BASE64 = "base64";

    private static final class HeadersWithData {

        final MimeMultipart headers;
        final String data;

        HeadersWithData(MimeMultipart headers, String data) {
            this.headers = headers;
            this.data = data;
        }
    }

    static MimeMessage finalizeMessage(Session session, MimeMessage msg, String data) throws MessagingException, IOException {
        msg.saveChanges();
        BiByteArrayStream bis = new BiByteArrayStream();
        writeMessage(bis.output(), msg, data);
        return new MimeMessage(session, bis.input());
    }

    static String fillMessage(CryptoFactory factory, MimeMessage msg, MimeMessage originalMsg,
                              String charset, InputStreamSource src, String comment,
                              SignedPart sp,
                              SignKey[] signCerts, EncryptKey encryptCert, boolean detachSignature) throws MessagingException, IOException, CryptoException {
        boolean createMultipart;
        if (detachSignature) {
            if (sp != null && sp.rawData == null) {
                createMultipart = false;
            } else {
                createMultipart = encryptCert == null && signCerts != null && signCerts.length == 1;
            }
        } else {
            createMultipart = false;
        }
        if (createMultipart) {
            return signedOnly(factory, msg, charset, src, comment, sp, signCerts[0]);
        } else {
            return signEncrypt(factory, msg, originalMsg, charset, src, comment, sp, encryptCert, signCerts);
        }
    }

    private static String signEncrypt(CryptoFactory factory,
                                      MimeMessage msg, MimeMessage originalMsg,
                                      String charset, InputStreamSource src, String comment,
                                      SignedPart sp,
                                      EncryptKey encryptCert, SignKey[] signCerts) throws MessagingException, IOException, CryptoException {
        List<EnvelopeDesc> envelopes = new ArrayList<EnvelopeDesc>();
        int si = 0;
        if (sp != null && signCerts != null && signCerts.length > 0) {
            envelopes.add(new EnvelopeDesc(sp.rawData, sp.rawSignature, signCerts[si++]));
        }
        if (signCerts != null) {
            while (si < signCerts.length) {
                SignKey signCert = signCerts[si++];
                envelopes.add(new EnvelopeDesc(EnvelopeDesc.SIGN, signCert, null));
            }
        }
        if (encryptCert != null) {
            envelopes.add(new EnvelopeDesc(EnvelopeDesc.ENCRYPT, null, encryptCert));
        }
        return signEncrypt(factory, msg, originalMsg, charset, src, comment, envelopes);
    }

    private static final class Enveloper {

        private final CryptoFactory factory;

        private MimePart current;
        private String currentData;

        private Enveloper(CryptoFactory factory, MimePart current, String currentData) {
            this.factory = factory;
            this.current = current;
            this.currentData = currentData;
        }

        private Crypto getCrypto() {
            return factory.getCrypto();
        }

        void run(EnvelopeDesc envelope) throws MessagingException, IOException, CryptoException {
            String smime;
            if (envelope.type == EnvelopeDesc.COSIGN) {
                String cosignedData;
                if (envelope.rawData == null) {
                    cosignedData = getCrypto().cosignData(null, envelope.rawSignature.getInputStream(), envelope.signKey, false);
                } else {
                    HeadersWithData hwd = signedMultipart(
                        null, factory, null, null, null, envelope.rawData, envelope.rawSignature, envelope.signKey
                    );
                    current = new MimeBodyPart();
                    current.setHeader(CONTENT_TYPE, hwd.headers.getContentType());
                    current.setHeader(CONTENT_TRANSFER_ENCODING, "7bit");
                    currentData = hwd.data;
                    return;
                }

                smime = "signed-data";
                currentData = cosignedData;
            } else {
                String text;
                if (currentData != null) {
                    text = writeMessage(current, currentData);
                } else {
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    MimeUtil.writePart(bos, current);
                    text = bos.toString();
                }
                if (envelope.type == EnvelopeDesc.ENCRYPT) {
                    String encryptedData = getCrypto().encryptData(text, envelope.encryptKey);

                    smime = "enveloped-data";
                    currentData = encryptedData;
                } else {
                    String signedData = getCrypto().signData(text, envelope.signKey, false);

                    smime = "signed-data";
                    currentData = signedData;
                }
            }
            current = new MimeBodyPart();
            current.setHeader(CONTENT_TYPE, "application/pkcs7-mime; smime-type=\"" + smime + "\"");
            current.setHeader(CONTENT_TRANSFER_ENCODING, BASE64);
            current.setDisposition(Part.ATTACHMENT);
            current.setFileName(ENVELOPE_FILE);
        }

        MimePart getPart() {
            return current;
        }

        String getData() {
            return currentData;
        }
    }

    static String signEncrypt(CryptoFactory factory,
                              MimeMessage msg, MimeMessage originalMsg, String charset, InputStreamSource src, String comment,
                              List<EnvelopeDesc> envelopes) throws IOException, MessagingException, CryptoException {
        Enveloper enveloper;
        if (src != null) {
            MimeBodyPart plainPart = new MimeBodyPart();
            fillPlain(plainPart, src.getName(), charset, comment);
            String plainData = MimeUtil.base64(src.open());
            enveloper = new Enveloper(factory, plainPart, plainData);
        } else {
            enveloper = new Enveloper(factory, originalMsg, null);
        }

        for (EnvelopeDesc envelope : envelopes) {
            enveloper.run(envelope);
        }

        MimePart part = enveloper.getPart();
        Enumeration<?> headers = part.getAllHeaderLines();
        while (headers.hasMoreElements()) {
            String line = (String) headers.nextElement();
            msg.addHeaderLine(line);
        }
        return enveloper.getData();
    }

    private static void fillPlain(MimeBodyPart plainPart, String fileName, String charset, String comment) throws MessagingException, UnsupportedEncodingException {
        plainPart.setHeader(CONTENT_TYPE, "text/plain");
        plainPart.setHeader(CONTENT_TRANSFER_ENCODING, BASE64);
        ContentDisposition disposition = new ContentDisposition(Part.ATTACHMENT);
        disposition.setParameter("filename", MimeUtility.encodeText(fileName, charset, "Q"));
        plainPart.setHeader("Content-Disposition", disposition.toString());
        plainPart.setDescription(comment, charset);
    }

    private static String signedOnly(CryptoFactory factory, MimeMessage msg,
                                     String charset, InputStreamSource src, String comment,
                                     SignedPart sp,
                                     SignKey signCert) throws MessagingException, IOException, CryptoException {
        HeadersWithData hwd = signedMultipart(
            "This is an S/MIME multipart signed message", factory,
            charset, src, comment,
            sp == null ? null : sp.rawData, sp == null ? null : sp.rawSignature,
            signCert
        );
        msg.setContent(hwd.headers);
        return hwd.data;
    }

    private static HeadersWithData signedMultipart(String preamble, CryptoFactory factory,
                                                   String charset, InputStreamSource src, String comment,
                                                   String rawData, Part rawSignature,
                                                   SignKey signCert) throws IOException, MessagingException, CryptoException {
        MimeMultipart mp = new MimeMultipart("signed; protocol=\"application/pkcs7-signature\"");

        MimeBodyPart plainPart;
        String data;
        String signature;
        if (src != null) {
            plainPart = new MimeBodyPart();
            fillPlain(plainPart, src.getName(), charset, comment);
            mp.addBodyPart(plainPart);
            data = MimeUtil.base64(src.open());

            String text = writeMessage(plainPart, data);

            signature = factory.getCrypto().signData(text, signCert, true);
        } else {
            plainPart = null;
            data = null;
            signature = factory.getCrypto().cosignData(rawData, rawSignature.getInputStream(), signCert, true);
        }

        MimeBodyPart signPart = new MimeBodyPart();
        signPart.setHeader(CONTENT_TYPE, "application/pkcs7-signature");
        signPart.setHeader(CONTENT_TRANSFER_ENCODING, BASE64);
        signPart.setDisposition(Part.ATTACHMENT);
        signPart.setFileName(SIGNATURE_FILE);
        mp.addBodyPart(signPart);

        if (preamble != null) {
            mp.setPreamble(preamble);
        }

        ContentType contentType = new ContentType(mp.getContentType());
        String boundary = "--" + contentType.getParameter("boundary");

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        LineOutputStream los = new LineOutputStream(bos);
        los.writeln();
        if (preamble != null) {
            los.writeln(mp.getPreamble());
        }
        los.writeln();
        los.writeln(boundary);
        if (plainPart != null && data != null) {
            writeMessage(los, plainPart, data);
            los.writeln();
        } else if (rawData != null) {
            los.writeln(rawData);
        } else {
            los.writeln(MimeUtil.base64(rawSignature.getInputStream()));
        }
        los.writeln(boundary);
        writeMessage(los, signPart, signature);
        los.writeln(boundary + "--");
        los.flush();

        String encrypted = bos.toString();

        return new HeadersWithData(mp, encrypted);
    }

    private static String writeMessage(MimePart part, String data) throws MessagingException, IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        writeMessage(bos, part, data);
        return bos.toString();
    }

    private static void writeMessage(OutputStream os, MimePart part, String data) throws MessagingException, IOException {
        MimeUtil.composePart(os, part, data);
    }
}
