package smime.bc;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.io.Streams;
import smime.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.util.*;

final class CryptoImpl implements Crypto {

    private static final String BC = KeyData.BC;

    private final List<KeyData> storedKeys;

    CryptoImpl(List<KeyData> storedKeys) {
        this.storedKeys = storedKeys;
    }

    private static SignInfo verify(SignerInformation signer, X509CertificateHolder holder) {
        boolean ok = false;
        String error = null;
        try {
            ok = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(holder));
        } catch (Exception ex) {
            error = ex.toString();
        }
        Map<String, String> info = new HashMap<>();
        info.put("name", holder.getSubject().toString());
        return new SignInfo(null, info, ok, error);

    }

    @SuppressWarnings("unchecked")
    private static void getSigners(CMSSignedDataParser sp, List<SignInfo> sis) throws CMSException {
        Store<?> certificates = sp.getCertificates();
        Collection<SignerInformation> signers = sp.getSignerInfos().getSigners();
        for (SignerInformation signer : signers) {
            Collection<?> matches = certificates.getMatches(signer.getSID());
            for (Object match : matches) {
                X509CertificateHolder holder = (X509CertificateHolder) match;
                SignInfo si = verify(signer, holder);
                sis.add(si);
            }
        }
    }

    private static String extractData(CMSSignedDataParser sp) throws IOException {
        byte[] bytes;
        try (InputStream is = sp.getSignedContent().getContentStream()) {
            bytes = Streams.readAll(is);
        }
        return new String(bytes);
    }

    public String getSigners(InputStream data, List<SignInfo> signers) throws CryptoException, IOException {
        try {
            DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
            CMSSignedDataParser sp = new CMSSignedDataParser(digestCalculatorProvider, data);
            String rawData = extractData(sp);
            getSigners(sp, signers);
            return rawData;
        } catch (CMSException | OperatorCreationException ex) {
            throw new CryptoExceptionImpl(ex);
        }
    }

    public void getSignersDetached(String data, InputStream signature, List<SignInfo> signers) throws CryptoException, IOException {
        try {
            DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
            CMSSignedDataParser sp = new CMSSignedDataParser(digestCalculatorProvider, new CMSTypedStream(raw(data)), signature);
            sp.getSignedContent().drain();
            getSigners(sp, signers);
        } catch (CMSException | OperatorCreationException ex) {
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
            CMSSignedData cms = gen.generate(new CMSProcessableByteArray(data.getBytes()), !detached);
            return base64(cms.getEncoded());
        } catch (CMSException | CertificateEncodingException | OperatorCreationException ex) {
            throw new CryptoExceptionImpl(ex);
        }
    }

    public String encryptData(String data, EncryptKey key) throws CryptoException, IOException {
        EncryptKeyImpl impl = (EncryptKeyImpl) key;
        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        try {
            gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(impl.certificate).setProvider(BC));
            OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build();
            CMSEnvelopedData cms = gen.generate(new CMSProcessableByteArray(data.getBytes()), encryptor);
            return base64(cms.getEncoded());
        } catch (CertificateEncodingException | CMSException ex) {
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
                if (storedKey.getSerialNumber().equals(serialNumber)) {
                    Recipient recipient = new JceKeyTransEnvelopedRecipient(storedKey.privateKey);
                    return new String(ri.getContent(recipient));
                }
            }
            throw new CryptoExceptionImpl("Serial number " + serialNumber + " not found for decrypt");
        } catch (CMSException ex) {
            throw new CryptoExceptionImpl(ex);
        }
    }

    public String cosignData(String data, InputStream signature, SignKey key) throws CryptoException, IOException {
        SignKeyImpl impl = (SignKeyImpl) key;
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        try {
            DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
            CMSSignedDataParser sp;
            boolean encapsulate;
            if (data != null) {
                sp = new CMSSignedDataParser(digestCalculatorProvider, new CMSTypedStream(raw(data)), signature);
                encapsulate = false;
            } else {
                sp = new CMSSignedDataParser(digestCalculatorProvider, signature);
                data = extractData(sp);
                encapsulate = true;
            }
            Store<?> store = new JcaCertStore(Collections.singletonList(impl.certificate));
            ContentSigner contentSigner = new JcaContentSignerBuilder(KeyData.ALGORITHM).setProvider(BC).build(impl.key);
            gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(digestCalculatorProvider).build(contentSigner, impl.certificate));
            gen.addCertificates(sp.getCertificates());
            gen.addCertificates(store);
            gen.addSigners(sp.getSignerInfos());
            CMSSignedData cms = gen.generate(new CMSProcessableByteArray(data.getBytes()), encapsulate);
            return base64(cms.getEncoded());
        } catch (CMSException | CertificateEncodingException | OperatorCreationException ex) {
            throw new CryptoExceptionImpl(ex);
        }
    }

    private static String base64(byte[] data) throws IOException {
        return MimeUtil.base64(new ByteArrayInputStream(data));
    }

    private static InputStream raw(String str) {
        return new ByteArrayInputStream(str.getBytes());
    }
}
