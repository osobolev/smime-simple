package ru.fe.crypto.mail;

import ru.fe.crypto.mail.impl.CryptoFactoryImpl;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import java.io.IOException;

public class Test {

    public static void main(String[] args) throws MessagingException, IOException, CryptoException {
        CryptoFactory factory = new CryptoFactoryImpl();
        InputStreamSource src = null; // todo
        MimeMessage message = SMimeSend.createMessage(
            factory, SMimeReceive.createFakeSession(), "Windows-1251", src, "Comment", new SignKey[] {}, null, true
        );
    }
}
