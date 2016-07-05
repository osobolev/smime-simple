package ru.fe.crypto.mail;

final class EnvelopeDesc {

    static final int ENCRYPT = 0;
    static final int SIGN = 1;
    static final int COSIGN = 2;

    final int type;
    final SignKey signKey;
    final EncryptKey encryptKey;
    final String rawData;
    final String rawSignature;

    EnvelopeDesc(int type, SignKey signKey, EncryptKey encryptKey) {
        this.type = type;
        this.rawData = null;
        this.rawSignature = null;
        this.signKey = signKey;
        this.encryptKey = encryptKey;
    }

    EnvelopeDesc(String rawData, String rawSignature, SignKey key) {
        this.type = COSIGN;
        this.rawData = rawData;
        this.rawSignature = rawSignature;
        this.signKey = key;
        this.encryptKey = null;
    }
}
