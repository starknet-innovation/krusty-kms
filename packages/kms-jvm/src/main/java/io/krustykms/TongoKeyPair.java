package io.krustykms;

import java.util.Objects;

public final class TongoKeyPair {
    private final Felt privateKey;
    private final ProjectivePoint publicKey;

    public TongoKeyPair(Felt privateKey, ProjectivePoint publicKey) {
        this.privateKey = Objects.requireNonNull(privateKey);
        this.publicKey = Objects.requireNonNull(publicKey);
    }

    public Felt privateKey() { return privateKey; }
    public ProjectivePoint publicKey() { return publicKey; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TongoKeyPair)) return false;
        TongoKeyPair that = (TongoKeyPair) o;
        return privateKey.equals(that.privateKey) && publicKey.equals(that.publicKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(privateKey, publicKey);
    }

    @Override
    public String toString() {
        return "TongoKeyPair(privateKey=" + privateKey + ", publicKey=" + publicKey + ")";
    }
}
