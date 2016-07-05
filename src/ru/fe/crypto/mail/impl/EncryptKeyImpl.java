package ru.fe.crypto.mail.impl;

import ru.fe.crypto.mail.EncryptKey;

import java.security.cert.X509Certificate;

final class EncryptKeyImpl implements EncryptKey {

    final X509Certificate certificate;

    EncryptKeyImpl(X509Certificate certificate) {
        this.certificate = certificate;
    }
}
