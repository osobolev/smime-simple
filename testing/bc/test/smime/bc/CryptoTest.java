package smime.bc;

import com.sun.mail.util.BASE64DecoderStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import smime.BiByteArrayStream;
import smime.Crypto;
import smime.CryptoException;
import smime.SignInfo;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class CryptoTest {

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

    public static void main(String[] args) throws CryptoException, IOException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, CertificateException {
        Security.addProvider(new BouncyCastleProvider());

        KeyData key1 = KeyData.create(1);
        KeyData key2 = KeyData.create(2);

        CryptoFactoryImpl factory = new CryptoFactoryImpl(Arrays.asList(key1, key2));
        Crypto crypto = factory.getCrypto();
        {
            String encrypted = crypto.encryptData("Xyzzy", key1.getEncryptKey());
            String s = crypto.decryptData(unbase64(encrypted));
            System.out.println(s);
        }
        {
            String undetached = crypto.signData("ABBA", key1.getSignKey(), false);
            List<SignInfo> signers = new ArrayList<SignInfo>();
            String data = crypto.getSigners(unbase64(undetached), signers);
            System.out.println(data);
            System.out.println(signers);
        }
        {
            String data = "ABBA";
            String detached = crypto.signData(data, key1.getSignKey(), true);
            List<SignInfo> dsigners = new ArrayList<SignInfo>();
            crypto.getSignersDetached(data, unbase64(detached), dsigners);
            System.out.println(dsigners);
        }
        {
            String data = "ABBA";
            boolean detached = true;
            String sdetached = crypto.signData(data, key1.getSignKey(), detached);
            String cosigned = crypto.cosignData(data, unbase64(sdetached), key2.getSignKey(), detached);
            List<SignInfo> signers = new ArrayList<SignInfo>();
            crypto.getSignersDetached(data, unbase64(cosigned), signers);
            System.out.println(signers);
        }
        {
            String data = "ABBA";
            boolean detached = false;
            String sundetached = crypto.signData(data, key1.getSignKey(), detached);
            String cosigned = crypto.cosignData(null, unbase64(sundetached), key2.getSignKey(), detached);
            List<SignInfo> signers = new ArrayList<SignInfo>();
            String sdata = crypto.getSigners(unbase64(cosigned), signers);
            System.out.println(sdata);
            System.out.println(signers);
        }
    }
}
