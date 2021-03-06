package smime.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import smime.*;
import smime.bc.CryptoFactoryImpl;
import smime.bc.KeyData;
import smime.rand.RandomMessageBuilder;

import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeMessage;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.List;

public final class TestCoSign {

    public static void main(String[] args) throws MessagingException, IOException, CryptoException, OperatorCreationException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());

        KeyData key1 = KeyData.create(1);
        KeyData key2 = KeyData.create(2);
        List<KeyData> keys = Arrays.asList(key1, key2);
        CryptoFactoryImpl factory = new CryptoFactoryImpl(keys);
        InputStreamSource src = RandomMessageBuilder.SOURCE;

        Session session = SMimeReceive.createFakeSession();
        MimeMessage message = SMimeSend.createMessage(
            factory, session, "Windows-1251", src, "Comment",
            new SignKey[] {key1.getSignKey()}, null, true
        );

        MimeMessage cosigned = SMimeSend.cosignMessage(
            factory, session, message, new SignKey[] {key2.getSignKey()}, null
        );

        new PartWalker(factory, (part, signed) -> {
            try {
                System.out.println(part.getContent());
            } catch (Exception ex) {
                ex.printStackTrace();
            }
            System.out.println(signed);
        }).walk(cosigned);
    }
}
