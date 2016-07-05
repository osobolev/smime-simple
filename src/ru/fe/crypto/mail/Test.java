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
        MimeMessage message = SMimeSend.createMessage(
            factory, SMimeReceive.createFakeSession(), "Windows-1251", src, "Comment",
            new SignKey[] {factory.getSignKey()}, factory.getEncryptKey(), true
        );

        message.writeTo(System.out);
        System.out.flush();

        SignedPart part = SMimeReceive.read(factory, message);
        System.out.println(part.dataPart.getContent());
    }
}
