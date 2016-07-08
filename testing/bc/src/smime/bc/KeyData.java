package smime.bc;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.Recipient;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import smime.EncryptKey;
import smime.SignKey;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

public final class KeyData {

    static final String ALGORITHM = "SHA1withRSA";
    static final String BC = "BC";

    public final X509Certificate certificate;
    public final PrivateKey privateKey;

    public KeyData(X509Certificate certificate, PrivateKey privateKey) {
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    public static KeyData create(int n) throws CertificateException, OperatorCreationException, NoSuchProviderException, NoSuchAlgorithmException {
        return create(System.currentTimeMillis() + 1000L * n, n);
    }

    public static KeyData create(long serialNum, int n) throws CertificateException, OperatorCreationException, NoSuchProviderException, NoSuchAlgorithmException {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", BC);
        gen.initialize(1024);
        KeyPair pair = gen.generateKeyPair();
        PublicKey pub = pair.getPublic();
        PrivateKey priv = pair.getPrivate();

        long now = System.currentTimeMillis();
        long year = 365 * 24 * 60 * 60 * 1000L;

        X500Name name = new X500Name("CN=Test" + n + ", O=ATS, L=Moscow, C=RU");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            name,
            BigInteger.valueOf(serialNum),
            new Date(now - year), new Date(now + year), name,
            pub
        );
        X509CertificateHolder holder = builder.build(new JcaContentSignerBuilder(ALGORITHM).setProvider(BC).build(priv));
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(holder);

        return new KeyData(cert, priv);
    }

    public SignKey getSignKey() {
        return new SignKeyImpl(certificate, privateKey);
    }

    public EncryptKey getEncryptKey() {
        return new EncryptKeyImpl(certificate);
    }

    public BigInteger getSerialNumber() {
        return certificate.getSerialNumber();
    }
}
