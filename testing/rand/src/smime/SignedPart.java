package smime;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Part;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimePart;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

public final class SignedPart {

    public final Message message;
    public final SignInfo[] signatures;
    public final Part dataPart;
    final String rawData;
    final Part rawSignature;
    public final Throwable error;

    SignedPart(MimeMessage message, MimePart dataPart, SignInfo[] signatures,
               String rawData, Part rawSignature, Throwable error) {
        this.message = message;
        this.dataPart = dataPart;
        this.signatures = signatures;
        this.rawData = rawData;
        this.rawSignature = rawSignature;
        this.error = error;
    }

    SignedPart(Message message, Part dataPart, List<SignInfo> signatures, String rawData, Part rawSignature) throws IOException, MessagingException {
        this(message, dataPart, signatures.toArray(new SignInfo[signatures.size()]), rawData, rawSignature, null);
    }

    SignedPart(Message message, Part dataPart, SignInfo[] signatures, String rawData, Part rawSignature, Throwable error) throws IOException, MessagingException {
        this.message = message;
        this.dataPart = dataPart;
        copyStream(dataPart.getInputStream(), new OutputStream() {
            public void write(int b) {
            }
        });
        this.signatures = signatures;
        this.rawData = rawData;
        this.rawSignature = rawSignature;
        this.error = error;
    }

    /**
     * Не закрывает потоки!
     */
    public static void copyStream(InputStream in, OutputStream out) throws IOException {
        byte[] arr = new byte[1024];
        int read;
        while ((read = in.read(arr)) != -1) {
            out.write(arr, 0, read);
        }
    }
}
