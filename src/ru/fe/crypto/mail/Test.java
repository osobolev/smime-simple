package ru.fe.crypto.mail;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import ru.fe.crypto.mail.impl.CryptoFactoryImpl;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;

public final class Test {

    public static void main(String[] args) throws MessagingException, IOException, CryptoException, OperatorCreationException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());

        CryptoFactoryImpl factory = CryptoFactoryImpl.create();
        InputStreamSource src = new MemStreamSource("abba.txt", "Xyzzy".getBytes());

//        {
//            MimeMessage message = SMimeSend.createMessage(
//                factory, SMimeReceive.createFakeSession(), "Windows-1251", src, "Comment",
//                new SignKey[] {factory.getSignKey()}, null, true
//            );
//            message.writeTo(System.out);
//            System.out.flush();
//            check(factory, message);
//        }

        for (int detach = 0; detach < 2; detach++) {
            for (int sign = 0; sign < 3; sign++) {
                SignKey[] signCerts = new SignKey[sign];
                for (int j = 0; j < sign; j++) {
                    signCerts[j] = factory.getSignKey();
                }
                for (int enc = 0; enc < 2; enc++) {
                    EncryptKey encryptKey = enc == 0 ? null : factory.getEncryptKey();
                    System.out.println(sign + " " + enc + " " + detach);
                    MimeMessage message = SMimeSend.createMessage(
                        factory, SMimeReceive.createFakeSession(), "Windows-1251", src, "Comment",
                        signCerts, encryptKey, detach != 0
                    );
                    check(factory, message);
                }
            }
        }
    }

    private static void check(CryptoFactoryImpl factory, MimeMessage message) throws CryptoException, IOException, MessagingException {
        SignedPart part = SMimeReceive.read(factory, message);
        String content = (String) part.dataPart.getContent();
        if (!"Xyzzy".equals(content))
            throw new IllegalStateException(content);
    }
}
