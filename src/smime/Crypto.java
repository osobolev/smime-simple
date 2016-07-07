package smime;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

public interface Crypto {

    // Reading:

    /**
     * @param data raw data to verify
     * @return raw signed ASCII data
     * @param signers signers' data is added to this list
     */
    String getSigners(InputStream data, List<SignInfo> signers) throws CryptoException, IOException;

    /**
     * @param data raw data to verify (must be ASCII)
     * @param signature raw signature to verify
     * @param signers signers' data is added to this list
     */
    void getSignersDetached(String data, InputStream signature, List<SignInfo> signers) throws CryptoException, IOException;

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

    /**
     * @param data raw data to co-sign (must be ASCII). If null then signature contains both data and signature.
     * @param signature raw data (if data is null then data+signature, else detached signature)
     * @return BASE64-encoded signature
     */
    String cosignData(String data, InputStream signature, SignKey key, boolean detached) throws CryptoException, IOException;
}
