package smime.bc;

import smime.SignKey;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

final class SignKeyImpl implements SignKey {

    final X509Certificate certificate;
    final PrivateKey key;

    SignKeyImpl(X509Certificate certificate, PrivateKey key) {
        this.certificate = certificate;
        this.key = key;
    }
}
