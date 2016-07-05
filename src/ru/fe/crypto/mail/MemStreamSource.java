package ru.fe.crypto.mail;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

public final class MemStreamSource implements InputStreamSource {

    private final String name;
    private final byte[] data;

    public MemStreamSource(String name, byte[] data) {
        this.name = name;
        this.data = data;
    }

    public InputStream open() {
        return new ByteArrayInputStream(data);
    }

    public String getName() {
        return name;
    }
}
