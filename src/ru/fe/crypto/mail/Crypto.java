package ru.fe.crypto.mail;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

public interface Crypto {

    // Reading:

    final class SignerData {

        public final List<SignInfo> signers;
        /**
         * @return raw signed ASCII data
         */
        public final String data;

        public SignerData(List<SignInfo> signers, String data) {
            this.signers = signers;
            this.data = data;
        }
    }

    /**
     * @param data raw data to verify
     */
    SignerData getSigners(InputStream data) throws CryptoException, IOException;

    List<SignInfo> getSignersDetached(InputStream data, InputStream signature) throws CryptoException, IOException;

    /**
     * @param data raw data to decrypt
     * @return raw decrypted ASCII data
     */
    String decryptData(InputStream data) throws CryptoException, IOException;

    // Writing:

    /**
     * @param data raw data to sign (must be ASCII)
     * @return BASE64-encoded signature
     */
    String signData(String data, SignKey key, boolean detached) throws CryptoException, IOException;

    /**
     * @param data raw data to encrypt (must be ASCII)
     * @return BASE64-encoded encrypted data
     */
    String encryptData(String data, EncryptKey key) throws CryptoException, IOException;

    // Co-sign:

    String cosignData(String data, String signature, SignKey key, boolean detached) throws CryptoException, IOException;
}
