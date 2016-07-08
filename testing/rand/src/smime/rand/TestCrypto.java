package smime.rand;

import com.sun.mail.util.BASE64DecoderStream;
import smime.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public final class TestCrypto {

    private static InputStream unbase64(String str) throws IOException {
        BASE64DecoderStream stream = new BASE64DecoderStream(new ByteArrayInputStream(str.getBytes()));
        BiByteArrayStream bis = new BiByteArrayStream();
        while (true) {
            int c = stream.read();
            if (c < 0)
                break;
            bis.output().write(c);
        }
        return bis.input();
    }

    private static void checkEqual(String s1, String s2) {
        if (!s1.equals(s2))
            throw new IllegalStateException("'" + s1 + "' <> '" + s2 + "'");
    }

    private static void checkSize(List<?> list, int n) {
        if (list.size() != n)
            throw new IllegalStateException(list.size() + " <> " + n);
    }

    public static void test(CryptoFactory factory, Random rnd, boolean printSignatures, SignKey sign1, SignKey sign2, EncryptKey enc1) throws IOException, CryptoException {
        String data = RandomMessageBuilder.randomString(rnd);
        test(factory, data, printSignatures, sign1, sign2, enc1);
    }

    public static void test(CryptoFactory factory, String data, boolean printSignatures, SignKey sign1, SignKey sign2, EncryptKey enc1) throws IOException, CryptoException {
        Crypto crypto = factory.getCrypto();
        {
            String encrypted = crypto.encryptData(data, enc1);
            String decrypted = crypto.decryptData(unbase64(encrypted));
            checkEqual(data, decrypted);
        }
        {
            String undetached = crypto.signData(data, sign1, false);
            List<SignInfo> signers = new ArrayList<SignInfo>();
            String sdata = crypto.getSigners(unbase64(undetached), signers);
            checkEqual(data, sdata);
            checkSize(signers, 1);
            if (printSignatures) {
                System.out.println(signers);
            }
        }
        {
            String detached = crypto.signData(data, sign1, true);
            List<SignInfo> dsigners = new ArrayList<SignInfo>();
            crypto.getSignersDetached(data, unbase64(detached), dsigners);
            checkSize(dsigners, 1);
            if (printSignatures) {
                System.out.println(dsigners);
            }
        }
        {
            String sdetached = crypto.signData(data, sign1, true);
            String cosigned = crypto.cosignData(data, unbase64(sdetached), sign2);
            List<SignInfo> signers = new ArrayList<SignInfo>();
            crypto.getSignersDetached(data, unbase64(cosigned), signers);
            checkSize(signers, 2);
            if (printSignatures) {
                System.out.println(signers);
            }
        }
        {
            String sundetached = crypto.signData(data, sign1, false);
            String cosigned = crypto.cosignData(null, unbase64(sundetached), sign2);
            List<SignInfo> signers = new ArrayList<SignInfo>();
            String sdata = crypto.getSigners(unbase64(cosigned), signers);
            checkEqual(data, sdata);
            checkSize(signers, 2);
            if (printSignatures) {
                System.out.println(signers);
            }
        }
    }
}
