package smime.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import smime.impl.KeyData;

import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public final class Test {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        List<KeyData> keys = new ArrayList<KeyData>();
        for (int i = 1; i <= 3; i++) {
            keys.add(KeyData.create(i));
        }
        RandomMessageBuilder randomBuilder = new RandomMessageBuilder(keys);

        Random rnd = new Random(0);
        for (int i = 0; i < 1000; i++) {
            System.out.println(i + 1);
            RandomMessage rm = randomBuilder.create(rnd);
            randomBuilder.check(rm);
            RandomMessage cosigned = randomBuilder.cosign(rm, rnd);
            randomBuilder.check(cosigned);
        }
    }
}
