package ru.fe.crypto.mail.impl;

import ru.fe.crypto.mail.SignKey;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public final class SignKeyImpl implements SignKey {

    final X509Certificate certificate;
    final PrivateKey key;

    public SignKeyImpl(X509Certificate certificate, PrivateKey key) {
        this.certificate = certificate;
        this.key = key;
    }
}
