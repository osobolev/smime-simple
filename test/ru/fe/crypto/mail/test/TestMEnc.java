package ru.fe.crypto.mail.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import ru.fe.crypto.mail.BiByteArrayStream;
import ru.fe.crypto.mail.InputStreamSource;
import ru.fe.crypto.mail.PartBuilder;
import ru.fe.crypto.mail.SMimeReceive;
import ru.fe.crypto.mail.impl.CryptoFactoryImpl;
import ru.fe.crypto.mail.impl.KeyData;

import javax.mail.Header;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

public final class TestMEnc {

    public static void main(String[] args) throws OperatorCreationException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, IOException, MessagingException {
        Security.addProvider(new BouncyCastleProvider());

        KeyData key1 = KeyData.create(1);
        KeyData key2 = KeyData.create(2);
        List<KeyData> keys = Arrays.asList(key1, key2);
        CryptoFactoryImpl factory = new CryptoFactoryImpl(keys);
        InputStreamSource src = RandomMessageBuilder.SOURCE;

        Session session = SMimeReceive.createFakeSession();

        PartBuilder builder = new PartBuilder(factory, "Windows-1251");
        MimeBodyPart text = builder.createText("Hello!");
        MimeBodyPart file = builder.createFile(src, "text/plain", "Comment");
        MimeBodyPart multi = PartBuilder.createMulti(text, file);
        MimeMessage message = PartBuilder.toMessage(session, multi);
        message.writeTo(System.out);
        System.out.flush();
        System.out.println("++++++++++++++++++++++++++++++++++++++");

        BiByteArrayStream bis = new BiByteArrayStream();
        message.writeTo(bis.output());
        MimeBodyPart mbp = new MimeBodyPart(bis.input());
        Enumeration<?> extraHeaders = mbp.getNonMatchingHeaders(new String[] {"Content-Type", "Content-Transfer-Encoding", "Content-Description", "Content-Disposition"});
        while (extraHeaders.hasMoreElements()) {
            Header header = (Header) extraHeaders.nextElement();
            mbp.removeHeader(header.getName());
        }
        mbp.writeTo(System.out);
        System.out.flush();
        System.out.println("++++++++++++++++++++++++++++++++++++++");

        MimeMessage message2 = PartBuilder.toMessage(session, mbp);
        message2.writeTo(System.out);
        System.out.flush();
    }
}
