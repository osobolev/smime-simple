package ru.fe.crypto.mail;

import com.sun.mail.util.LineOutputStream;

import javax.mail.MessagingException;
import javax.mail.internet.MimePart;
import java.io.Closeable;
import java.io.IOException;
import java.util.Enumeration;

final class MimeUtil {

    static void writeHeaders(MimePart part, LineOutputStream los) throws MessagingException, IOException {
        Enumeration<?> lines = part.getAllHeaderLines();
        while (lines.hasMoreElements()) {
            String line = (String) lines.nextElement();
            los.writeln(line);
        }
        los.writeln();
    }

    static void close(Closeable c) {
        try {
            c.close();
        } catch (IOException ex) {
            // ignore
        }
    }
}
