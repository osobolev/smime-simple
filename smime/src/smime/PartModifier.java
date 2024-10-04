package smime;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import java.io.IOException;

public interface PartModifier {

    void modify(MimeBodyPart part) throws MessagingException, IOException;
}
