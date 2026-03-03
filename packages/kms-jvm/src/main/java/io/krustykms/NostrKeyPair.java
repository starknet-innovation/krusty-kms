package io.krustykms;

import java.util.Arrays;
import java.util.Objects;

public final class NostrKeyPair {
    private final byte[] privateKey;
    private final byte[] publicKeyXonly;

    public NostrKeyPair(byte[] privateKey, byte[] publicKeyXonly) {
        Objects.requireNonNull(privateKey);
        Objects.requireNonNull(publicKeyXonly);
        this.privateKey = privateKey.clone();
        this.publicKeyXonly = publicKeyXonly.clone();
    }

    public byte[] privateKey() { return privateKey.clone(); }
    public byte[] publicKeyXonly() { return publicKeyXonly.clone(); }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof NostrKeyPair)) return false;
        NostrKeyPair that = (NostrKeyPair) o;
        return Arrays.equals(privateKey, that.privateKey)
            && Arrays.equals(publicKeyXonly, that.publicKeyXonly);
    }

    @Override
    public int hashCode() {
        return Objects.hash(Arrays.hashCode(privateKey), Arrays.hashCode(publicKeyXonly));
    }

    @Override
    public String toString() {
        return "NostrKeyPair(privateKey=[32 bytes], publicKeyXonly=[32 bytes])";
    }
}
