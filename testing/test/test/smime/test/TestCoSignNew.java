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

public final class TestCoSignNew {

    public static void main(String[] args) throws MessagingException, IOException, CryptoException, OperatorCreationException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());

        KeyData key1 = KeyData.create(1);
        KeyData key2 = KeyData.create(2);
        List<KeyData> keys = Arrays.asList(key1, key2);
        CryptoFactoryImpl factory = new CryptoFactoryImpl(keys);
        InputStreamSource src = RandomMessageBuilder.SOURCE;

        Session session = SMimeReceive.createFakeSession();

        PartBuilder builder = new PartBuilder(factory);
        SMimePart file = PartBuilder.createFile(src, "text/plain", "Windows-1251", "Comment");
        SMimePart signed = builder.sign(file, key1.getSignKey(), true);
        MimeMessage message = PartBuilder.toMessage(session, signed);
        message.setSubject("Subj");

        CoSignWalker walker = new CoSignWalker(factory, key2.getSignKey());
        CoSignedMessage cosigned = walker.walk(message);
        MimeMessage cosignedMessage = cosigned.getMessage(session);
        cosignedMessage.writeTo(System.out);
        System.out.flush();

        new PartWalker(factory, (part, signInfos) -> {
            try {
                System.out.println(part.getContent());
            } catch (Exception ex) {
                ex.printStackTrace();
            }
            System.out.println(signInfos);
        }).walk(cosignedMessage);
    }
}
