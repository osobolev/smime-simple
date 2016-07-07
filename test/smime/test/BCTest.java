package smime.test;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMEToolkit;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import smime.CryptoException;
import smime.impl.CryptoFactoryImpl;
import smime.impl.KeyData;
import smime.rand.RandomMessageBuilder;

import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Properties;

public final class BCTest {

    public static void main(String[] args) throws OperatorCreationException, MessagingException, CMSException, CertificateException, SMIMEException, NoSuchAlgorithmException, NoSuchProviderException, IOException, CryptoException {
        Security.addProvider(new BouncyCastleProvider());

        DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
        SMIMEToolkit tk = new SMIMEToolkit(digestCalculatorProvider);
        MimeBodyPart filePart = new MimeBodyPart();
        filePart.setContent("Xyzzy", "text/plain");
        filePart.setFileName("abba.txt");
        KeyData key1 = KeyData.create(1);
        X509Certificate cert = key1.certificate;
        MimeMultipart signed = tk.sign(
            filePart,
            new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC").build("SHA1withRSA", key1.privateKey, cert)
        );
        MimeBodyPart encrypted = tk.encrypt(
            signed,
            new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes128_CBC).setProvider("BC").build(),
            new JceKeyTransRecipientInfoGenerator(cert).setProvider("BC")
        );
        MimeMessage message = new MimeMessage(Session.getDefaultInstance(new Properties()));
        message.setContent(encrypted.getContent(), encrypted.getContentType());
        message.saveChanges();
        message.writeTo(System.out);
        System.out.flush();
        RandomMessageBuilder.check(new CryptoFactoryImpl(Collections.singletonList(key1)), message);
    }
}
