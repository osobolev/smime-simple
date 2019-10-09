package smime;

import com.sun.mail.util.BASE64EncoderStream;
import com.sun.mail.util.CRLFOutputStream;
import com.sun.mail.util.LineOutputStream;

import javax.mail.MessagingException;
import javax.mail.Part;
import javax.mail.internet.MimePart;
import java.io.*;
import java.util.Enumeration;

public final class MimeUtil {

    public static void writePart(OutputStream os, Part part) throws IOException, MessagingException {
        part.writeTo(new CRLFOutputStream(os));
    }

    public static String base64(InputStream is) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        OutputStream os = new BASE64EncoderStream(bos, 64);
        while (true) {
            int b = is.read();
            if (b < 0)
                break;
            os.write(b);
        }
        os.close();
        return bos.toString();
    }

    static InputStream serialize(Part part) throws MessagingException, IOException {
        BiByteArrayStream bis = new BiByteArrayStream();
        writePart(bis.output(), part);
        return bis.input();
    }

    static String partToString(Part part) throws IOException, MessagingException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        writePart(bos, part);
        return bos.toString();
    }

    static void composePart(OutputStream os, MimePart headers, String base64) throws MessagingException, IOException {
        LineOutputStream los = new LineOutputStream(os);
        Enumeration<?> lines = headers.getAllHeaderLines();
        while (lines.hasMoreElements()) {
            String line = (String) lines.nextElement();
            los.writeln(line);
        }
        los.writeln();
        los.writeln(base64); // todo: remove extra eoln???
    }
}
