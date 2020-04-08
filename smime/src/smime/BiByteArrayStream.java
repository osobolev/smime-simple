package smime;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

public final class BiByteArrayStream {

    private final MyByteArrayOutputStream bos = new MyByteArrayOutputStream();

    public OutputStream output() {
        return bos;
    }

    public InputStream input() {
        return bos.toOut();
    }

    public String toString() {
        return bos.toString();
    }

    public int size() {
        return bos.size();
    }

    private static final class MyByteArrayOutputStream extends ByteArrayOutputStream {

        InputStream toOut() {
            return new ByteArrayInputStream(buf, 0, count);
        }
    }
}
