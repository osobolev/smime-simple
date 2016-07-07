package ru.fe.crypto.mail;

import javax.mail.MessagingException;
import javax.mail.Part;
import java.io.IOException;
import java.util.List;

public interface PartCallback {

    void leafPart(Part part, List<SignInfo> signed) throws MessagingException, IOException;
}
