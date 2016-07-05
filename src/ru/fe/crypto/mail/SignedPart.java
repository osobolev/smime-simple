package ru.fe.crypto.mail;

import com.sun.mail.util.CRLFOutputStream;
import ru.fe.common.StreamUtils;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Part;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimePart;
import java.io.IOException;
import java.io.OutputStream;
import java.util.List;

public final class SignedPart {

    public final Message message;
    public final SignInfo[] signatures;
    final String rawData;
    final String rawSignature;
    public final Throwable error;

    SignedPart(MimeMessage message, MimePart dataPart, SignInfo[] signatures,
               String rawData, String rawSignature, Throwable error) {
        this.message = message;
        this.signatures = signatures;
        this.rawData = rawData;
        this.rawSignature = rawSignature;
        this.error = error;
    }

    SignedPart(Message message, Part dataPart, List<SignInfo> signatures, String rawData, String rawSignature) throws IOException, MessagingException {
        this(message, dataPart, signatures.toArray(new SignInfo[signatures.size()]), rawData, rawSignature, null);
    }

    SignedPart(Message message, Part dataPart, SignInfo[] signatures, String rawData, String rawSignature, Throwable error) throws IOException, MessagingException {
        this.message = message;
        StreamUtils.copyStream(dataPart.getInputStream(), new OutputStream() {
            public void write(int b) {
            }
        });
        this.signatures = signatures;
        this.rawData = rawData;
        this.rawSignature = rawSignature;
        this.error = error;
    }

    public static void write(Part part, OutputStream os) throws IOException, MessagingException {
        part.writeTo(new CRLFOutputStream(os));
    }
}
