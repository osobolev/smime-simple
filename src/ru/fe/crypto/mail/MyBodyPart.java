package ru.fe.crypto.mail;

import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.Part;
import javax.mail.internet.MimeBodyPart;
import java.io.IOException;
import java.io.InputStream;

public final class MyBodyPart {

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

    private MyBodyPart(CommitablePart part) {
        this.part = part;
    }

    static MyBodyPart complex(Multipart mp) throws MessagingException {
        CommitablePart complexPart = new CommitablePart();
        complexPart.setContent(mp);
        return new MyBodyPart(complexPart);
    }

    static MyBodyPart simple(InputStream is) throws MessagingException {
        return new MyBodyPart(new CommitablePart(is));
    }

    static MyBodyPart simple(Part part) throws IOException, MessagingException {
        if (part instanceof CommitablePart) {
            return new MyBodyPart((CommitablePart) part);
        } else {
            return simple(PartWalker.serialize(part));
        }
    }

    MimeBodyPart getPart() throws MessagingException {
        part.commit();
        return part;
    }
}
