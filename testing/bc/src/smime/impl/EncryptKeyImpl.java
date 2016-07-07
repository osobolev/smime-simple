package smime.impl;

import smime.EncryptKey;

import java.security.cert.X509Certificate;

final class EncryptKeyImpl implements EncryptKey {

    final X509Certificate certificate;

    EncryptKeyImpl(X509Certificate certificate) {
        this.certificate = certificate;
    }
}
