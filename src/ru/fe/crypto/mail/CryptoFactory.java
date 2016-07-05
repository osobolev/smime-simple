package ru.fe.crypto.mail;

import java.io.IOException;
import java.io.InputStream;

public interface CryptoFactory {

    Crypto getCrypto();

    Data fromRaw(InputStream is) throws IOException;
}
