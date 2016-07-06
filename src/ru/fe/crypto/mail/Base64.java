package ru.fe.crypto.mail;

import com.sun.mail.util.BASE64EncoderStream;

import java.io.*;

public final class Base64 {

    public static String base64(byte[] data) throws IOException {
        return base64(new ByteArrayInputStream(data));
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
        is.close();
        return bos.toString();
    }
}
