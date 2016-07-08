package smime.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import smime.CryptoException;
import smime.bc.CryptoFactoryImpl;
import smime.bc.KeyData;
import smime.rand.TestCrypto;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Random;

public final class CryptoTest {

    public static void main(String[] args) throws OperatorCreationException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, IOException, CryptoException {
        Security.addProvider(new BouncyCastleProvider());

        KeyData key1 = KeyData.create(1);
        KeyData key2 = KeyData.create(2);

        CryptoFactoryImpl factory = new CryptoFactoryImpl(Arrays.asList(key1, key2));
        Random rnd = new Random(0);
        TestCrypto.test(factory, rnd, true, key1.getSignKey(), key2.getSignKey(), key1.getEncryptKey());
    }
}
