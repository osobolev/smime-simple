package ru.fe.crypto.mail.impl;

import com.sun.mail.util.BASE64DecoderStream;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
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
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.*;

final class CryptoImpl implements Crypto {

    private static final Charset CHARSET = Charset.defaultCharset();
    private static final String BC = KeyData.BC;

    private final List<KeyData> storedKeys;

    CryptoImpl(List<KeyData> storedKeys) {
        this.storedKeys = storedKeys;
    }

    private static List<SignInfo> getSigners(CMSSignedDataParser sp) throws CMSException, OperatorCreationException, CertificateException {
        List<SignInfo> sis = new ArrayList<SignInfo>();
        Store<?> certificates = sp.getCertificates();
        Collection<SignerInformation> signers = sp.getSignerInfos().getSigners();
        for (SignerInformation signer : signers) {
            Collection<?> matches = certificates.getMatches(signer.getSID());
            for (Object match : matches) {
                X509CertificateHolder holder = (X509CertificateHolder) match;
                boolean ok = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(holder));
                Map<String, String> info = new HashMap<String, String>();
                info.put("name", holder.getSubject().toString());
                sis.add(new SignInfo(null, info, ok));
            }
        }
        return sis;
    }

    private static String extractData(CMSSignedDataParser sp) throws IOException {
        InputStream is = sp.getSignedContent().getContentStream();
        byte[] bytes = StreamUtils.toByteArray(is);
        is.close();
        return new String(bytes, CHARSET);
    }

    public SignerData getSigners(InputStream data) throws CryptoException, IOException {
        try {
            DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
            CMSSignedDataParser sp = new CMSSignedDataParser(digestCalculatorProvider, data);
            String rawData = extractData(sp);
            List<SignInfo> sis = getSigners(sp);
            return new SignerData(sis, rawData);
        } catch (CMSException ex) {
            throw new CryptoExceptionImpl(ex);
        } catch (OperatorCreationException ex) {
            throw new CryptoExceptionImpl(ex);
        } catch (CertificateException ex) {
            throw new CryptoExceptionImpl(ex);
        }
    }

    public List<SignInfo> getSignersDetached(InputStream data, InputStream signature) throws CryptoException, IOException {
        try {
            DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
            CMSSignedDataParser sp = new CMSSignedDataParser(digestCalculatorProvider, new CMSTypedStream(data), signature);
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
            ContentSigner contentSigner = new JcaContentSignerBuilder(KeyData.ALGORITHM).setProvider(BC).build(impl.key);
            DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
            gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(digestCalculatorProvider).build(contentSigner, impl.certificate));
            gen.addCertificates(store);
            CMSSignedData cms = gen.generate(new CMSProcessableByteArray(data.getBytes(CHARSET)), !detached);
            return MimeUtil.base64(cms.getEncoded());
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
            gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(impl.certificate).setProvider(BC));
            OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build();
            CMSEnvelopedData cms = gen.generate(new CMSProcessableByteArray(data.getBytes(CHARSET)), encryptor);
            return MimeUtil.base64(cms.getEncoded());
        } catch (CertificateEncodingException ex) {
            throw new CryptoExceptionImpl(ex);
        } catch (CMSException ex) {
            throw new CryptoExceptionImpl(ex);
        }
    }

    public String decryptData(InputStream data) throws CryptoException, IOException {
        try {
            CMSEnvelopedDataParser parser = new CMSEnvelopedDataParser(data);
            Iterator<RecipientInformation> i = parser.getRecipientInfos().iterator();
            if (!i.hasNext())
                throw new CryptoExceptionImpl("No encryption recipients found");
            RecipientInformation ri = i.next();
            KeyTransRecipientId rid = (KeyTransRecipientId) ri.getRID();
            BigInteger serialNumber = rid.getSerialNumber();
            for (KeyData storedKey : storedKeys) {
                if (storedKey.matches(serialNumber)) {
                    Recipient recipient = storedKey.getRecipient();
                    return new String(ri.getContent(recipient), CHARSET);
                }
            }
            throw new CryptoExceptionImpl("Serial number " + serialNumber + " not found for decrypt");
        } catch (CMSException ex) {
            throw new CryptoExceptionImpl(ex);
        }
    }

    public String cosignData(String data, InputStream signature, SignKey key, boolean detached) throws CryptoException, IOException {
        SignKeyImpl impl = (SignKeyImpl) key;
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        try {
            DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
            CMSSignedDataParser sp;
            if (data != null) {
                sp = new CMSSignedDataParser(digestCalculatorProvider, new CMSTypedStream(raw(data)), signature);
            } else {
                sp = new CMSSignedDataParser(digestCalculatorProvider, signature);
                data = extractData(sp);
            }
            Store<?> store = new JcaCertStore(Collections.singletonList(impl.certificate));
            ContentSigner contentSigner = new JcaContentSignerBuilder(KeyData.ALGORITHM).setProvider(BC).build(impl.key);
            gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(digestCalculatorProvider).build(contentSigner, impl.certificate));
            gen.addCertificates(sp.getCertificates());
            gen.addCertificates(store);
            gen.addSigners(sp.getSignerInfos());
            CMSSignedData cms = gen.generate(new CMSProcessableByteArray(data.getBytes(CHARSET)), !detached);
            return MimeUtil.base64(cms.getEncoded());
        } catch (CMSException ex) {
            throw new CryptoExceptionImpl(ex);
        } catch (CertificateEncodingException ex) {
            throw new CryptoExceptionImpl(ex);
        } catch (OperatorCreationException ex) {
            throw new CryptoExceptionImpl(ex);
        }
    }

    private static InputStream raw(String str) {
        return new ByteArrayInputStream(str.getBytes(CHARSET));
    }

    private static InputStream unbase64(String str) throws IOException {
        BASE64DecoderStream stream = new BASE64DecoderStream(raw(str));
        BiByteArrayStream bis = new BiByteArrayStream();
        while (true) {
            int c = stream.read();
            if (c < 0)
                break;
            bis.output().write(c);
        }
        return bis.input();
    }

    @SuppressWarnings("UseOfSystemOutOrSystemErr")
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
            SignerData signers = crypto.getSigners(unbase64(undetached));
            System.out.println(signers.data);
            System.out.println(signers.signers);
        }
        {
            String data = "ABBA";
            String detached = crypto.signData(data, key1.getSignKey(), true);
            List<SignInfo> dsigners = crypto.getSignersDetached(raw(data), unbase64(detached));
            System.out.println(dsigners);
        }
        {
            String data = "ABBA";
            boolean detached = true;
            String sdetached = crypto.signData(data, key1.getSignKey(), detached);
            String cosigned = crypto.cosignData(data, unbase64(sdetached), key2.getSignKey(), detached);
            List<SignInfo> signers = crypto.getSignersDetached(raw(data), unbase64(cosigned));
            System.out.println(signers);
        }
        // todo: can cosign data detached which is signed undetached and v/v?
        {
            String data = "ABBA";
            boolean detached = false;
            String sundetached = crypto.signData(data, key1.getSignKey(), detached);
            String cosigned = crypto.cosignData(null, unbase64(sundetached), key2.getSignKey(), detached);
            SignerData signers = crypto.getSigners(unbase64(cosigned));
            System.out.println(signers.data);
            System.out.println(signers.signers);
        }
    }
}
