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

public final class Test1 {

    public static void main(String[] args) throws MessagingException, IOException, CryptoException, OperatorCreationException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());

        KeyData key1 = KeyData.create(1);
        KeyData key2 = KeyData.create(2);
        List<KeyData> keys = Arrays.asList(key1, key2);
        CryptoFactoryImpl factory = new CryptoFactoryImpl(keys);
        InputStreamSource src = RandomMessageBuilder.SOURCE;
        Session session = SMimeReceive.createFakeSession();

//        {
//            MimeMessage message = SMimeSend.createMessage(
//                factory, session, "Windows-1251", src, "Comment",
//                new SignKey[] {key1.getSignKey()}, null, true
//            );
//            message.writeTo(System.out);
//            System.out.flush();
//        }
//        System.out.println("++++++++++++++++++++++++++++++++++++++++++++++++++++");

        {
            PartBuilder builder = new PartBuilder(factory);
            SMimePart filePart = PartBuilder.createFile(src, "text/plain", "Windows-1251", "Comment");
            SMimePart textPart = PartBuilder.createText("Hello!", "Windows-1251");
            SMimePart multiPart = PartBuilder.createMulti(textPart, filePart);
            SMimePart signed = builder.signDetached(multiPart, key1.getSignKey());
//            MyBodyPart encrypted = builder.encrypt(multiPart.getPart(), key1.getEncryptKey());
            MimeMessage message = PartBuilder.toMessage(session, signed);
            message.writeTo(System.out);
            System.out.flush();
            RandomMessageBuilder.check(factory, message);

            CoSignedMessage cosigned = new CoSignWalker(factory, key1.getSignKey()).walk(message);
            if (!cosigned.isSigned()) {
                cosigned = cosigned.sign(builder, key1.getSignKey(), true);
            }
            RandomMessageBuilder.check(factory, cosigned.getMessage(session));
        }
    }
}
