package ru.fe.crypto.mail.impl;

import ru.fe.crypto.mail.Crypto;
import ru.fe.crypto.mail.CryptoFactory;

import java.util.List;

public final class CryptoFactoryImpl implements CryptoFactory {

    private final List<KeyData> keys;

    public CryptoFactoryImpl(List<KeyData> keys) {
        this.keys = keys;
    }

    public Crypto getCrypto() {
        return new CryptoImpl(keys);
    }
}
