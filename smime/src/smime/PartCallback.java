package smime;

import jakarta.mail.MessagingException;
import jakarta.mail.Part;

import java.io.IOException;
import java.util.List;

public interface PartCallback {

    void leafPart(Part part, List<SignInfo> signed) throws MessagingException, IOException;
}
