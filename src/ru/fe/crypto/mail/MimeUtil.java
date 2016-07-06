package ru.fe.crypto.mail;

import com.sun.mail.util.LineOutputStream;

import javax.mail.MessagingException;
import javax.mail.internet.MimePart;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Enumeration;

final class MimeUtil {

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

    /**
     * Не закрывает потоки!
     */
    static void copyStreamEoln(InputStream in, OutputStream out) throws IOException {
        byte[] arr = new byte[1024];
        int read;
        boolean prevR = false;
        byte[] eoln = {'\r', '\n'};
        while ((read = in.read(arr)) >= 0) {
            for (int i = 0; i < read; i++) {
                byte ch = arr[i];
                if (prevR) {
                    if (ch == '\n') {
                        out.write(eoln);
                        prevR = false;
                    } else if (ch == '\r') {
                        out.write(eoln);
                    } else {
                        out.write(eoln);
                        out.write(ch);
                        prevR = false;
                    }
                } else {
                    if (ch == '\n') {
                        out.write(eoln);
                    } else if (ch == '\r') {
                        prevR = true;
                    } else {
                        out.write(ch);
                    }
                }
            }
        }
        if (prevR) {
            out.write(eoln);
        }
    }

    static void close(Closeable c) {
        try {
            c.close();
        } catch (IOException ex) {
            // ignore
        }
    }
}
