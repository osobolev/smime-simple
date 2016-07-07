package smime.impl;

import smime.CryptoException;

public final class CryptoExceptionImpl extends CryptoException {

    public CryptoExceptionImpl(String message) {
        super(message);
    }

    public CryptoExceptionImpl(Throwable cause) {
        super(cause);
    }
}
