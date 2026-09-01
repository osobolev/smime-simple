package smime;

import javax.mail.Header;
import javax.mail.MessagingException;
import javax.mail.internet.*;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;

public final class CoSignWalker {

    public static final String[] STANDARD_HEADERS = {
        "Date", "From", "Sender", "Reply-To",
        "To", "Cc", "Bcc",
        "Message-ID", "In-Reply-To", "References",
        "Subject", "Comments", "Keywords"
    };
    
    private final CryptoFactory factory;
    private final PartBuilder builder;
    private final SignKey addKey;
    private final String[] preserveNestedMessageHeaders;

    public CoSignWalker(CryptoFactory factory, SignKey addKey, String[] preserveNestedMessageHeaders) {
        this.factory = factory;
        this.builder = new PartBuilder(factory);
        this.addKey = addKey;
        this.preserveNestedMessageHeaders = preserveNestedMessageHeaders;
    }

    public CoSignWalker(CryptoFactory factory, SignKey addKey) {
        this(factory, addKey, null);
    }

    public CoSignedMessage walk(MimeMessage message) throws MessagingException, IOException, CryptoException {
        boolean[] signed = new boolean[1];
        SMimePart part = walk(message, signed);
        return new CoSignedMessage(part, signed[0]);
    }

    private Crypto getCrypto() {
        return factory.getCrypto();
    }

    @SuppressWarnings("TailRecursion")
    private SMimePart walk(MimePart part, boolean[] signed) throws MessagingException, IOException, CryptoException {
        if (part.isMimeType("multipart/signed")) {
            signed[0] = true;
            if (addKey == null) {
                return SMimePart.simple(part);
            } else {
                return builder.cosignDetached(part, addKey);
            }
        } else if (part.isMimeType("application/pkcs7-mime")) {
            ContentType contentType = new ContentType(part.getContentType());
            String smime = contentType.getParameter("smime-type");
            if ("signed-data".equals(smime)) {
                signed[0] = true;
                if (addKey == null) {
                    return SMimePart.simple(part);
                } else {
                    return builder.cosign(part, addKey);
                }
            } else {
                String decrypted;
                try (InputStream is = part.getInputStream()) {
                    decrypted = getCrypto().decryptData(is);
                }
                return walk(SMimePart.newPart(decrypted), signed);
            }
        } else if (part.isMimeType("multipart/*")) {
            MimeMultipart mp = (MimeMultipart) part.getContent();
            String contentType = mp.getContentType();
            int p = contentType.indexOf('/');
            MimeMultipart newMp;
            if (p >= 0) {
                newMp = new MimeMultipart(contentType.substring(p + 1));
            } else {
                newMp = new MimeMultipart();
            }
            newMp.setPreamble(mp.getPreamble());
            int count = mp.getCount();
            for (int i = 0; i < count; i++) {
                MimeBodyPart child = (MimeBodyPart) mp.getBodyPart(i);
                SMimePart newChild = walk(child, signed);
                newMp.addBodyPart(newChild.getPart());
            }
            return SMimePart.complex(newMp);
        } else if (part.isMimeType("message/rfc822")) {
            MimeMessage nested = new MimeMessage(null, part.getInputStream());
            SMimePart signedContent = walk(nested, signed);
            if (preserveNestedMessageHeaders != null) {
                MimeMessage wrappedMessage = PartBuilder.toMessage(null, signedContent);
                Enumeration<Header> headers = nested.getMatchingHeaders(preserveNestedMessageHeaders);
                while (headers.hasMoreElements()) {
                    Header header = headers.nextElement();
                    wrappedMessage.setHeader(header.getName(), header.getValue());
                }
                MimeBodyPart messagePart = SMimePart.newPart();
                messagePart.setContent(wrappedMessage, part.getContentType());
                return SMimePart.simple(messagePart);
            } else {
                return signedContent;
            }
        } else {
            return SMimePart.simple(part);
        }
    }
}
