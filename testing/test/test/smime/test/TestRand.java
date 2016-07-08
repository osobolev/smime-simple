package smime.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import smime.EncryptKey;
import smime.SignKey;
import smime.bc.CryptoFactoryImpl;
import smime.bc.KeyData;
import smime.rand.RandomMessageBuilder;

import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public final class TestRand {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        List<KeyData> keys = new ArrayList<KeyData>();
        List<SignKey> skeys = new ArrayList<SignKey>();
        List<EncryptKey> ekeys = new ArrayList<EncryptKey>();
        for (int i = 1; i <= 3; i++) {
            KeyData key = KeyData.create(i);
            keys.add(key);
            skeys.add(key.getSignKey());
            ekeys.add(key.getEncryptKey());
        }
        CryptoFactoryImpl factory = new CryptoFactoryImpl(keys);

        Random rnd = new Random(0);
        RandomMessageBuilder.runTests(skeys, ekeys, factory, rnd, 1000);
    }
}
