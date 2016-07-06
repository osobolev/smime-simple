package ru.fe.crypto.mail.test;

import ru.fe.crypto.mail.*;
import ru.fe.crypto.mail.impl.CryptoFactoryImpl;
import ru.fe.crypto.mail.impl.KeyData;

import javax.mail.MessagingException;
import javax.mail.Part;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import java.io.IOException;
import java.util.List;
import java.util.Random;

public final class RandomMessageBuilder {

    private static final String DATA = "Xyzzy";
    private static final String FILE_NAME = "abba.txt";

    public static final InputStreamSource SOURCE = new MemStreamSource(FILE_NAME, DATA.getBytes());

    private final CryptoFactoryImpl factory;
    private final List<KeyData> keys;
    private final PartBuilder builder;
    private final Session session = SMimeReceive.createFakeSession();

    RandomMessageBuilder(List<KeyData> keys) {
        this.keys = keys;
        this.factory = new CryptoFactoryImpl(keys);
        this.builder = new PartBuilder(factory);
    }

    RandomMessage create(Random rnd) throws MessagingException, IOException, CryptoException {
        StringBuilder buf = new StringBuilder();
        MimeMessage message;
        boolean isNew = rnd.nextBoolean();
        boolean compatible = true;
        boolean signed = false;
        if (isNew) {
            buf.append("New");
            MimeBodyPart filePart = PartBuilder.createFile(SOURCE, "text/plain", "Windows-1251", "Comment");
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
                    signed = true;
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
            message = PartBuilder.toMessage(session, current);
        } else {
            buf.append("Old");
            int sign = rnd.nextInt(3);
            SignKey[] signCerts = new SignKey[sign];
            for (int j = 0; j < sign; j++) {
                int k = rnd.nextInt(keys.size());
                buf.append(" Signed " + k);
                signCerts[j] = keys.get(k).getSignKey();
                signed = true;
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
                factory, session, "Windows-1251", SOURCE, "Comment",
                signCerts, encryptKey, detach
            );
        }
        return new RandomMessage(message, compatible, buf.toString(), signed);
    }

    void check(RandomMessage rm) throws Exception {
        try {
            checkNew(factory, rm.message);
            if (rm.oldCompatible) {
                checkOld(factory, rm.message);
            }
        } catch (Exception ex) {
            System.out.println(rm.description);
            rm.message.writeTo(System.out);
            System.out.flush();
            throw ex;
        }
    }

    RandomMessage cosign(RandomMessage rm, Random rnd) throws MessagingException, IOException, CryptoException {
        int k = rnd.nextInt(keys.size());
        SignKey signKey = keys.get(k).getSignKey();
        if (rm.oldCompatible && rm.signed && rnd.nextBoolean()) {
            MimeMessage cosigned = SMimeSend.cosignMessage(factory, session, rm.message, new SignKey[] {signKey}, null);
            return new RandomMessage(cosigned, rm.oldCompatible, rm.description + " Old cosigned " + k, true);
        } else {
            CoSignedMessage cosigned = new CoSignWalker(factory, signKey).walk(rm.message);
            if (!cosigned.isSigned()) {
                boolean detached = rnd.nextBoolean();
                cosigned = cosigned.sign(builder, signKey, detached);
            }
            return new RandomMessage(cosigned.getMessage(session), rm.oldCompatible, rm.description + " Cosigned " + k, true);
        }
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
                for (SignInfo signInfo : signed) {
                    if (!signInfo.verified) {
                        throw new IllegalStateException("Not verified: " + signInfo.info);
                    }
                }
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
