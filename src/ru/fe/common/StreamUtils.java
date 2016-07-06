package ru.fe.common;

import java.io.*;

/**
 * Date: 08.06.2009
 *
 * @author enaku
 * todo: remove from here???
 */
public final class StreamUtils {

    /**
     * Не закрывает поток!
     */
    public static byte[] toByteArray(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        copyStream(in, out);
        out.flush();
        return out.toByteArray();
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

    /**
     * Не закрывает потоки!
     */
    public static void copyStreamEoln(InputStream in, OutputStream out) throws IOException {
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
}
