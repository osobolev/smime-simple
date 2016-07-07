package smime.impl;

import smime.Crypto;
import smime.CryptoFactory;

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
