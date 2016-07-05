package ru.fe.crypto.mail.impl;

import ru.fe.crypto.mail.CryptoFactory;
import ru.fe.crypto.mail.Crypto;

public final class CryptoFactoryImpl implements CryptoFactory {

    public Crypto getCrypto() {
        return new CryptoImpl(null);
    }
}
