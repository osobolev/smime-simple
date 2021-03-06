package smime.rand;

import smime.*;

import javax.mail.MessagingException;
import javax.mail.Part;
import javax.mail.Session;
import javax.mail.internet.MimeMessage;
import java.io.IOException;
import java.util.List;
import java.util.Random;

public final class RandomMessageBuilder {

    private static final String DATA = "Xyzzy";
    private static final String FILE_NAME = "abba.txt";

    public static final InputStreamSource SOURCE = new MemStreamSource(FILE_NAME, DATA.getBytes());

    private final CryptoFactory factory;
    private final List<SignKey> skeys;
    private final List<EncryptKey> ekeys;
    private final PartBuilder builder;
    private final Session session = SMimeReceive.createFakeSession();

    public RandomMessageBuilder(List<SignKey> skeys, List<EncryptKey> ekeys, CryptoFactory factory) {
        this.skeys = skeys;
        this.ekeys = ekeys;
        this.factory = factory;
        this.builder = new PartBuilder(factory);
    }

    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_";

    public static String randomString(Random rnd) {
        int len = rnd.nextInt(20) + 1;
        StringBuilder buf = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            int c = rnd.nextInt(ALPHABET.length());
            buf.append(ALPHABET.charAt(c));
        }
        return buf.toString();
    }

    public RandomMessage create(Random rnd) throws MessagingException, IOException, CryptoException {
        String fileName = randomString(rnd) + ".txt";
        String content = randomString(rnd);
        InputStreamSource src = new MemStreamSource(fileName, content.getBytes());
        StringBuilder buf = new StringBuilder();
        MimeMessage message;
        boolean isNew = rnd.nextBoolean();
        boolean compatible = true;
        boolean signed = false;
        if (isNew) {
            buf.append("New");
            SMimePart filePart = PartBuilder.createFile(src, "text/plain", "Windows-1251", "Comment");
            int envelopes = rnd.nextInt(5);
            SMimePart current = filePart;
            boolean wasDetached = false;
            boolean wasWrapped = false;
            for (int j = 0; j < envelopes; j++) {
                int envType = rnd.nextInt(11); // 0..10: 1..5 to sign, 5..10 to encrypt, 0 to add text
                if (envType == 0) {
                    int nparts = rnd.nextInt(2) + 2;
                    buf.append(" Wrapped " + nparts);
                    wasWrapped = true;
                    SMimePart[] parts = new SMimePart[nparts];
                    for (int k = 0; k < nparts - 1; k++) {
                        parts[k] = PartBuilder.createText("Hello " + (k + 1), "Windows-1251");
                    }
                    parts[nparts - 1] = current;
                    current = PartBuilder.createMulti(parts);
                } else if (envType <= 5) {
                    int k = rnd.nextInt(skeys.size());
                    buf.append(" Signed " + k);
                    SignKey signKey = skeys.get(k);
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
                    int k = rnd.nextInt(ekeys.size());
                    buf.append(" Encrypted " + k);
                    EncryptKey encryptKey = ekeys.get(k);
                    current = builder.encrypt(current, encryptKey);
                }
            }
            if (wasDetached || wasWrapped) {
                compatible = envelopes <= 1;
            }
            message = PartBuilder.toMessage(session, current);
        } else {
            buf.append("Old");
            int sign = rnd.nextInt(3);
            SignKey[] signCerts = new SignKey[sign];
            for (int j = 0; j < sign; j++) {
                int k = rnd.nextInt(skeys.size());
                buf.append(" Signed " + k);
                signCerts[j] = skeys.get(k);
                signed = true;
            }
            boolean detach = rnd.nextBoolean();
            buf.append(" " + (detach ? "Detach" : "No detach"));
            EncryptKey encryptKey;
            if (rnd.nextBoolean()) {
                int k = rnd.nextInt(ekeys.size());
                buf.append(" Encrypted " + k);
                encryptKey = ekeys.get(k);
            } else {
                encryptKey = null;
            }
            message = SMimeSend.createMessage(
                factory, session, "Windows-1251", src, "Comment",
                signCerts, encryptKey, detach
            );
        }
        return new RandomMessage(fileName, content, message, compatible, buf.toString(), signed);
    }

    public void check(RandomMessage rm) throws Exception {
        try {
            checkNew(factory, rm.message, rm.fileName, rm.content);
            if (rm.oldCompatible) {
                checkOld(factory, rm.message, rm.fileName, rm.content);
            }
        } catch (Exception ex) {
            System.out.println("File: " + rm.fileName);
            System.out.println("Content: " + rm.content);
            System.out.println(rm.description);
            rm.message.writeTo(System.out);
            System.out.flush();
            throw ex;
        }
    }

    public RandomMessage cosign(RandomMessage rm, Random rnd) throws MessagingException, IOException, CryptoException {
        int sk = rnd.nextInt(skeys.size());
        SignKey signKey = skeys.get(sk);
        if (rm.oldCompatible && rm.signed && rnd.nextBoolean()) {
            MimeMessage cosigned = SMimeSend.cosignMessage(factory, session, rm.message, new SignKey[] {signKey}, null);
            return new RandomMessage(
                rm.fileName, rm.content, cosigned, rm.oldCompatible, rm.description + " Old cosigned " + sk, true
            );
        } else {
            CoSignedMessage cosigned = new CoSignWalker(factory, signKey).walk(rm.message);
            String add = "";
            if (!cosigned.isSigned()) {
                boolean detached = rnd.nextBoolean();
                cosigned = cosigned.sign(builder, signKey, detached);
                add += " Detached";
            }
            if (rnd.nextBoolean()) {
                int ek = rnd.nextInt(ekeys.size());
                EncryptKey encryptKey = ekeys.get(ek);
                cosigned = cosigned.encrypt(builder, encryptKey);
                add += " Encrypted " + ek;
            }
            return new RandomMessage(
                rm.fileName, rm.content, cosigned.getMessage(session), rm.oldCompatible,
                rm.description + " Cosigned " + sk + add, true
            );
        }
    }

    public static void check(CryptoFactory factory, MimeMessage message) throws CryptoException, IOException, MessagingException {
        checkNew(factory, message, FILE_NAME, DATA);
        checkOld(factory, message, FILE_NAME, DATA);
    }

    private static void checkNew(CryptoFactory factory, MimeMessage message,
                                 String requiredFileName, String requiredContent) throws CryptoException, IOException, MessagingException {
        Part[] foundPart = new Part[1];
        PartWalker partWalker = new PartWalker(factory, (part, signed) -> {
            if (part.getFileName() != null) {
                foundPart[0] = part;
            }
            for (SignInfo signInfo : signed) {
                if (!signInfo.verified) {
                    throw new IllegalStateException("Not verified: " + signInfo.info + " (" + signInfo.error + ")");
                }
            }
        });
        partWalker.walk(message);
        check(foundPart[0], requiredFileName, requiredContent);
    }

    private static void checkOld(CryptoFactory factory, MimeMessage message,
                                 String requiredFileName, String requiredContent) throws CryptoException, IOException, MessagingException {
        SignedPart part = SMimeReceive.read(factory, message);
        check(part.dataPart, requiredFileName, requiredContent);
    }

    private static void check(Part part, String requiredFileName, String requiredContent) throws IOException, MessagingException {
        String fileName = null;
        String content = null;
        if (part != null) {
            fileName = part.getFileName();
            content = (String) part.getContent();
        }
        if (!requiredFileName.equals(fileName)) {
            throw new IllegalStateException(fileName);
        }
        if (!requiredContent.equals(content)) {
            throw new IllegalStateException(content);
        }
    }

    public static void runTests(List<SignKey> skeys, List<EncryptKey> ekeys, CryptoFactory factory, Random rnd, int n) throws Exception {
        RandomMessageBuilder randomBuilder = new RandomMessageBuilder(skeys, ekeys, factory);

        for (int i = 0; i < n; i++) {
            System.out.println(i + 1);
            RandomMessage rm = randomBuilder.create(rnd);
            randomBuilder.check(rm);
            RandomMessage cosigned = randomBuilder.cosign(rm, rnd);
            randomBuilder.check(cosigned);
        }
    }
}
