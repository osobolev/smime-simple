package ru.fe.crypto.mail;

import javax.mail.Part;
import java.util.List;

public interface PartCallback {

    void leafPart(Part part, List<SignInfo> signed);
}
