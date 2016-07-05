package ru.fe.crypto.mail;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

// todo: change String to other abstracted type
public interface Crypto {

    final class SignerData {

        public final List<SignInfo> signers;
        public final String data;

        public SignerData(List<SignInfo> signers, String data) {
            this.signers = signers;
            this.data = data;
        }
    }

    SignerData getSigners(InputStream data) throws CryptoException, IOException;

    List<SignInfo> getSignersDetached(InputStream data, InputStream signature) throws CryptoException, IOException;

    byte[] signData(String data, SignKey key, boolean detached) throws CryptoException, IOException;

    byte[] encryptData(String data, EncryptKey key) throws CryptoException, IOException;

    String decryptData(InputStream data) throws CryptoException, IOException;

    byte[] cosignData(String data, String signature, SignKey key, boolean detached) throws CryptoException;
}
