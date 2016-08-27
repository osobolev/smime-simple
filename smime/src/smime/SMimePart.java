package smime;

import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.Part;
import javax.mail.internet.MimeBodyPart;
import java.io.IOException;
import java.io.InputStream;

public final class SMimePart {

    private static final class CommitablePart extends MimeBodyPart {

        private boolean dirty = true;

        CommitablePart() {
        }

        CommitablePart(InputStream is) throws MessagingException {
            super(is);
        }

        public void commit() throws MessagingException {
            if (dirty) {
                updateHeaders();
                dirty = false;
            }
        }
    }

    private final CommitablePart part;

    private SMimePart(CommitablePart part) {
        this.part = part;
    }

    static SMimePart complex(Multipart mp) throws MessagingException {
        CommitablePart complexPart = new CommitablePart();
        complexPart.setContent(mp);
        return new SMimePart(complexPart);
    }

    static SMimePart simple(InputStream is) throws MessagingException {
        return new SMimePart(new CommitablePart(is));
    }

    static SMimePart simple(Part part) throws IOException, MessagingException {
        if (part instanceof CommitablePart) {
            return new SMimePart((CommitablePart) part);
        } else {
            return simple(MimeUtil.serialize(part));
        }
    }

    MimeBodyPart getPart() throws MessagingException {
        part.commit();
        return part;
    }
}
