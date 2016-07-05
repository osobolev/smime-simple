package ru.fe.crypto.mail.impl;

import com.sun.mail.util.BASE64DecoderStream;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import ru.fe.common.StreamUtils;
import ru.fe.crypto.mail.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

public final class CryptoImpl implements Crypto {

    private static final Charset CHARSET = Charset.defaultCharset(); // todo: US-ASCII

    private final PrivateKey storedKey;

    public CryptoImpl(PrivateKey storedKey) {
        this.storedKey = storedKey;
    }

    private static List<SignInfo> getSigners(CMSSignedDataParser sp) throws CMSException, OperatorCreationException, CertificateException {
        List<SignInfo> sis = new ArrayList<SignInfo>();
        Store<?> certificates = sp.getCertificates();
        Collection<SignerInformation> signers = sp.getSignerInfos().getSigners();
        for (SignerInformation signer : signers) {
            Collection<?> matches = certificates.getMatches(signer.getSID());
            for (Object match : matches) {
                X509CertificateHolder holder = (X509CertificateHolder) match;
                boolean ok = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(holder));
                if (ok) {
                    Map<String, String> info = new HashMap<String, String>();
                    info.put("name", holder.getSubject().toString());
                    sis.add(new SignInfo(null, info));
                }
            }
        }
        return sis;
    }

    public SignerData getSigners(String data) throws CryptoException, IOException {
        try {
            byte[] buf = unbase64(data);
            DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
            CMSSignedDataParser sp = new CMSSignedDataParser(digestCalculatorProvider, buf);
            InputStream is = sp.getSignedContent().getContentStream();
            byte[] bytes = StreamUtils.toByteArray(is);
            is.close();
            List<SignInfo> sis = getSigners(sp);
            return new SignerData(sis, new String(bytes, CHARSET));
        } catch (CMSException ex) {
            throw new CryptoExceptionImpl(ex);
        } catch (OperatorCreationException ex) {
            throw new CryptoExceptionImpl(ex);
        } catch (CertificateException ex) {
            throw new CryptoExceptionImpl(ex);
        }
    }

    public List<SignInfo> getSignersDetached(String data, String signature) throws CryptoException, IOException {
        try {
            byte[] buf = unbase64(signature);
            DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
            CMSSignedDataParser sp = new CMSSignedDataParser(digestCalculatorProvider, new CMSTypedStream(new ByteArrayInputStream(data.getBytes(CHARSET))), buf);
            sp.getSignedContent().drain();
            return getSigners(sp);
        } catch (CMSException ex) {
            throw new CryptoExceptionImpl(ex);
        } catch (OperatorCreationException ex) {
            throw new CryptoExceptionImpl(ex);
        } catch (CertificateException ex) {
            throw new CryptoExceptionImpl(ex);
        }
    }

    public String signData(String data, SignKey key, boolean detached) throws CryptoException, IOException {
        SignKeyImpl impl = (SignKeyImpl) key;
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        try {
            Store<?> store = new JcaCertStore(Collections.singletonList(impl.certificate));
            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(impl.key);
            DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
            gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(digestCalculatorProvider).build(contentSigner, impl.certificate));
            gen.addCertificates(store);
            CMSSignedData cms = gen.generate(new CMSProcessableByteArray(data.getBytes(CHARSET)), !detached);
//            return new String(cms.getEncoded(), CHARSET); // todo!!!
            return MimeUtil.base64(new ByteArrayInputStream(cms.getEncoded())); // todo: ???
        } catch (CMSException ex) {
            throw new CryptoExceptionImpl(ex);
        } catch (CertificateEncodingException ex) {
            throw new CryptoExceptionImpl(ex);
        } catch (OperatorCreationException ex) {
            throw new CryptoExceptionImpl(ex);
        }
    }

    public String encryptData(String data, EncryptKey key) throws CryptoException, IOException {
        EncryptKeyImpl impl = (EncryptKeyImpl) key;
        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        try {
            gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(impl.certificate).setProvider("BC"));
            OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider("BC").build();
            CMSEnvelopedData cms = gen.generate(new CMSProcessableByteArray(data.getBytes(CHARSET)), encryptor);
            return MimeUtil.base64(new ByteArrayInputStream(cms.getEncoded())); // todo: ???
        } catch (CertificateEncodingException ex) {
            throw new CryptoExceptionImpl(ex);
        } catch (CMSException ex) {
            throw new CryptoExceptionImpl(ex);
        }
    }

    public String decryptData(String data) throws CryptoException, IOException {
        try {
            byte[] buf = unbase64(data);
            CMSEnvelopedDataParser parser = new CMSEnvelopedDataParser(buf);
            Iterator<RecipientInformation> i = parser.getRecipientInfos().iterator();
            if (!i.hasNext())
                throw new CryptoExceptionImpl("No encryption recipients found");
            RecipientInformation ri = i.next();
            Recipient recipient = new JceKeyTransEnvelopedRecipient(storedKey);
            return new String(ri.getContent(recipient), CHARSET);
        } catch (CMSException ex) {
            throw new CryptoExceptionImpl(ex);
        }
    }

    private static byte[] unbase64(String partData) throws IOException {
        BASE64DecoderStream decoderStream = new BASE64DecoderStream(new ByteArrayInputStream(partData.getBytes(CHARSET)));
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        while (true) {
            int c = decoderStream.read();
            if (c < 0)
                break;
            buf.write(c);
        }
        return buf.toByteArray();
    }

    public String cosignData(String data, String signature, SignKey key, boolean detached) throws CryptoException {
        return null;
    }

    public static void main(String[] args) throws CryptoException, IOException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, CertificateException {
        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "BC");
        gen.initialize(1024);
        KeyPair pair = gen.generateKeyPair();
        PublicKey pub = pair.getPublic();
        PrivateKey priv = pair.getPrivate();

        long now = System.currentTimeMillis();
        long year = 365 * 24 * 60 * 60 * 1000L;

        X500Name name = new X500Name("CN=www.mockserver.com, O=MockServer, L=London, ST=England, C=UK");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            name,
            BigInteger.valueOf(now),
            new Date(now - year), new Date(now + year), name,
            pub
        );
        X509CertificateHolder holder = builder.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(priv));
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);

        CryptoImpl crypto = new CryptoImpl(priv);
        String encrypted = crypto.encryptData("Xyzzy", new EncryptKeyImpl(cert));
        System.out.println(encrypted);
        String s = crypto.decryptData(encrypted);
        System.out.println(s);

        String undetached = crypto.signData("ABBA", new SignKeyImpl(cert, priv), false);
        System.out.println(undetached);
        SignerData signers = crypto.getSigners(undetached);
        System.out.println(signers.data);
        System.out.println(signers.signers);

        String detached = crypto.signData("ABBA", new SignKeyImpl(cert, priv), true);
        System.out.println(detached);
        List<SignInfo> dsigners = crypto.getSignersDetached("ABBA", detached);
        System.out.println(dsigners);
    }
}
