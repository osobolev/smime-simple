package ru.fe.crypto.mail.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import ru.fe.crypto.mail.*;
import ru.fe.crypto.mail.impl.CryptoFactoryImpl;
import ru.fe.crypto.mail.impl.KeyData;

import javax.mail.MessagingException;
import javax.mail.Part;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import java.io.IOException;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

public final class Test {

    private static final String DATA = "Xyzzy";
    private static final String FILE_NAME = "abba.txt";

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        KeyData key1 = KeyData.create(1);
        KeyData key2 = KeyData.create(2);
        List<KeyData> keys = Arrays.asList(key1, key2);
        CryptoFactoryImpl factory = new CryptoFactoryImpl(keys);
        InputStreamSource src = new MemStreamSource(FILE_NAME, DATA.getBytes());

//        {
//            MimeMessage message = SMimeSend.createMessage(
//                factory, SMimeSend.createFakeSession(), "Windows-1251", src, "Comment",
//                new SignKey[] {key1.getSignKey()}, null, true
//            );
//            message.writeTo(System.out);
//            System.out.flush();
//            check(factory, message);
//        }

        PartBuilder builder = new PartBuilder(factory, "Windows-1251");
        Random rnd = new Random(0);
        for (int i = 0; i < 1000; i++) {
            System.out.println(i + 1);
            StringBuilder buf = new StringBuilder();
            MimeMessage message;
            boolean isNew = rnd.nextBoolean();
            boolean compatible = true;
            if (isNew) {
                buf.append("New");
                MimeBodyPart filePart = builder.createFile(src, "text/plain", "Comment");
                int envelopes = rnd.nextInt(5);
                MimeBodyPart current = filePart;
                boolean wasDetached = false;
                for (int j = 0; j < envelopes; j++) {
                    if (rnd.nextBoolean()) {
                        int k = rnd.nextInt(keys.size());
                        buf.append(" Signed " + k);
                        SignKey signKey = keys.get(k).getSignKey();
                        boolean detach = rnd.nextBoolean();
                        buf.append(" " + (detach ? "Detach" : "No detach"));
                        if (detach) {
                            current = builder.signDetached(current, signKey);
                            wasDetached = true;
                        } else {
                            current = builder.sign(current, signKey);
                        }
                    } else {
                        int k = rnd.nextInt(keys.size());
                        buf.append(" Encrypted " + k);
                        EncryptKey encryptKey = keys.get(k).getEncryptKey();
                        current = builder.encrypt(current, encryptKey);
                    }
                }
                if (wasDetached) {
                    compatible = envelopes <= 1;
                }
                message = PartBuilder.toMessage(SMimeReceive.createFakeSession(), current);
            } else {
                buf.append("Old");
                int sign = rnd.nextInt(3);
                SignKey[] signCerts = new SignKey[sign];
                for (int j = 0; j < sign; j++) {
                    int k = rnd.nextInt(keys.size());
                    buf.append(" Signed " + k);
                    signCerts[j] = keys.get(k).getSignKey();
                }
                boolean detach = rnd.nextBoolean();
                buf.append(" " + (detach ? "Detach" : "No detach"));
                EncryptKey encryptKey;
                if (rnd.nextBoolean()) {
                    int k = rnd.nextInt(keys.size());
                    buf.append(" Encrypted " + k);
                    encryptKey = keys.get(k).getEncryptKey();
                } else {
                    encryptKey = null;
                }
                message = SMimeSend.createMessage(
                    factory, SMimeReceive.createFakeSession(), "Windows-1251", src, "Comment",
                    signCerts, encryptKey, detach
                );
            }
            try {
                checkNew(factory, message);
                if (compatible) {
                    checkOld(factory, message);
                }
            } catch (Exception ex) {
                System.out.println(buf);
                message.writeTo(System.out);
                System.out.flush();
                throw ex;
            }
        }

//        for (int detach = 0; detach < 2; detach++) {
//            for (int sign = 0; sign < 3; sign++) {
//                SignKey[] signCerts = new SignKey[sign];
//                for (int j = 0; j < sign; j++) {
//                    signCerts[j] = keys.get(j).getSignKey();
//                }
//                for (int enc = 0; enc < 2; enc++) {
//                    EncryptKey encryptKey = enc == 0 ? null : key1.getEncryptKey();
//                    System.out.println(sign + " " + enc + " " + detach);
//                    MimeMessage message = SMimeSend.createMessage(
//                        factory, SMimeSend.createFakeSession(), "Windows-1251", src, "Comment",
//                        signCerts, encryptKey, detach != 0
//                    );
//                    check(factory, message);
//                }
//            }
//        }
    }

    public static void check(CryptoFactoryImpl factory, MimeMessage message) throws CryptoException, IOException, MessagingException {
        checkNew(factory, message);
        checkOld(factory, message);
    }

    private static void checkNew(CryptoFactoryImpl factory, MimeMessage message) throws CryptoException, IOException, MessagingException {
        final Part[] foundPart = new Part[1];
        PartWalker partWalker = new PartWalker(factory, new PartCallback() {
            public void leafPart(Part part, List<SignInfo> signed) {
                foundPart[0] = part;
            }
        });
        partWalker.walk(message);
        check(foundPart[0]);
    }

    private static void checkOld(CryptoFactoryImpl factory, MimeMessage message) throws CryptoException, IOException, MessagingException {
        SignedPart part = SMimeReceive.read(factory, message);
        check(part.dataPart);
    }

    private static void check(Part part) throws IOException, MessagingException {
        String fileName = null;
        String content = null;
        if (part != null) {
            fileName = part.getFileName();
            content = (String) part.getContent();
        }
        if (!FILE_NAME.equals(fileName)) {
            throw new IllegalStateException(fileName);
        }
        if (!DATA.equals(content)) {
            throw new IllegalStateException(content);
        }
    }
}
