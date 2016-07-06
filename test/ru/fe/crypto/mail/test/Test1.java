package ru.fe.crypto.mail.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import ru.fe.crypto.mail.*;
import ru.fe.crypto.mail.impl.CryptoFactoryImpl;
import ru.fe.crypto.mail.impl.KeyData;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
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
        InputStreamSource src = new MemStreamSource("abba.txt", "Xyzzy".getBytes());

        {
            MimeMessage message = SMimeSend.createMessage(
                factory, SMimeReceive.createFakeSession(), "Windows-1251", src, "Comment",
                new SignKey[] {key1.getSignKey()}, null, true
            );
            message.writeTo(System.out);
            System.out.flush();
        }

        System.out.println("++++++++++++++++++++++++++++++++++++++++++++++++++++");
        {
            PartBuilder builder = new PartBuilder(factory, "Windows-1251");
            MimeBodyPart filePart = builder.createFile(src, "text/plain", "Comment");
//            MimeBodyPart signed = builder.sign(filePart, key1.getSignKey());
            MimeBodyPart signed = filePart;
            for (int i = 0; i < 4; i++) {
                signed = builder.signDetached(signed, key1.getSignKey());
            }
//            MimeBodyPart encrypted = builder.encrypt(signed, key1.getEncryptKey());
            MimeMessage message = PartBuilder.toMessage(SMimeReceive.createFakeSession(), signed);
            message.writeTo(System.out);
            System.out.flush();
            Test.check(factory, message);
        }
    }
}
