package ru.fe.crypto.mail;

public abstract class CryptoException extends Exception {

    protected CryptoException() {
    }

    protected CryptoException(String message) {
        super(message);
    }

    protected CryptoException(String message, Throwable cause) {
        super(message, cause);
    }

    protected CryptoException(Throwable cause) {
        super(cause);
    }
}
