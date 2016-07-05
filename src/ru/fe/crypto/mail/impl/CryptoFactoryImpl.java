package ru.fe.crypto.mail.impl;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import ru.fe.crypto.mail.*;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

public final class CryptoFactoryImpl implements CryptoFactory {

    private final X509Certificate certificate;
    private final PrivateKey privateKey;

    public CryptoFactoryImpl(X509Certificate certificate, PrivateKey privateKey) {
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    public static CryptoFactoryImpl create() throws CertificateException, OperatorCreationException, NoSuchProviderException, NoSuchAlgorithmException {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "BC");
        gen.initialize(1024);
        KeyPair pair = gen.generateKeyPair();
        PublicKey pub = pair.getPublic();
        PrivateKey priv = pair.getPrivate();

        long now = System.currentTimeMillis();
        long year = 365 * 24 * 60 * 60 * 1000L;

        X500Name name = new X500Name("CN=www.mockserver.com, O=MockServer, L=London, ST=England, C=UK");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            name,
            BigInteger.valueOf(now),
            new Date(now - year), new Date(now + year), name,
            pub
        );
        X509CertificateHolder holder = builder.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(priv));
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);

        return new CryptoFactoryImpl(cert, priv);
    }

    public SignKey getSignKey() {
        return new SignKeyImpl(certificate, privateKey);
    }

    public EncryptKey getEncryptKey() {
        return new EncryptKeyImpl(certificate);
    }

    public Crypto getCrypto() {
        return new CryptoImpl(privateKey);
    }

    public Data fromRaw(InputStream is) throws IOException {
        return null; // todo
    }
}
