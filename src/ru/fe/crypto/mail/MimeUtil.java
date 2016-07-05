package ru.fe.crypto.mail;

import com.sun.mail.util.BASE64EncoderStream;
import com.sun.mail.util.LineOutputStream;

import javax.mail.MessagingException;
import javax.mail.internet.MimePart;
import java.io.*;
import java.util.Enumeration;

final class MimeUtil {

    static String base64(byte[] data) throws IOException {
        return base64(new ByteArrayInputStream(data));
    }

    static String base64(InputStream is) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        OutputStream os = new BASE64EncoderStream(bos, 64);
        while (true) {
            int b = is.read();
            if (b < 0)
                break;
            os.write(b);
        }
        os.close();
        is.close();
        return bos.toString();
    }

    static void writeHeaders(MimePart part, OutputStream os) throws MessagingException, IOException {
        LineOutputStream los = toLOS(os);
        Enumeration<?> lines = part.getAllHeaderLines();
        while (lines.hasMoreElements()) {
            String line = (String) lines.nextElement();
            los.writeln(line);
        }
        los.writeln();
        los.flush();
    }

    static LineOutputStream toLOS(OutputStream os) {
        return os instanceof LineOutputStream ? (LineOutputStream) os : new LineOutputStream(os);
    }
}
