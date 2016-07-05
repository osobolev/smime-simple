package ru.fe.crypto.mail;

import java.io.IOException;
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

    SignerData getSigners(String data) throws CryptoException, IOException;

    List<SignInfo> getSignersDetached(String data, String signature) throws CryptoException, IOException;

    String signData(String data, SignKey key, boolean detached) throws CryptoException, IOException;

    String encryptData(String data, EncryptKey key) throws CryptoException, IOException;

    String decryptData(String data) throws CryptoException, IOException;

    String cosignData(String data, String signature, SignKey key, boolean detached) throws CryptoException;
}
