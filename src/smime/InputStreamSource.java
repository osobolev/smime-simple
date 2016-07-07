package smime;

import java.io.IOException;
import java.io.InputStream;

public interface InputStreamSource {

    InputStream open() throws IOException;

    String getName();
}
