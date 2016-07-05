package ru.fe.crypto.mail.impl;

import ru.fe.crypto.mail.CryptoException;

public final class CryptoExceptionImpl extends CryptoException {

    public CryptoExceptionImpl(String message) {
        super(message);
    }

    public CryptoExceptionImpl(Throwable cause) {
        super(cause);
    }
}
