package io.krustykms;

import java.util.Objects;

public final class EthSignature {
    private final Felt rLow;
    private final Felt rHigh;
    private final Felt sLow;
    private final Felt sHigh;
    private final Felt v;

    public EthSignature(Felt rLow, Felt rHigh, Felt sLow, Felt sHigh, Felt v) {
        this.rLow = Objects.requireNonNull(rLow);
        this.rHigh = Objects.requireNonNull(rHigh);
        this.sLow = Objects.requireNonNull(sLow);
        this.sHigh = Objects.requireNonNull(sHigh);
        this.v = Objects.requireNonNull(v);
    }

    public Felt rLow() { return rLow; }
    public Felt rHigh() { return rHigh; }
    public Felt sLow() { return sLow; }
    public Felt sHigh() { return sHigh; }
    public Felt v() { return v; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof EthSignature)) return false;
        EthSignature that = (EthSignature) o;
        return rLow.equals(that.rLow) && rHigh.equals(that.rHigh)
            && sLow.equals(that.sLow) && sHigh.equals(that.sHigh)
            && v.equals(that.v);
    }

    @Override
    public int hashCode() {
        return Objects.hash(rLow, rHigh, sLow, sHigh, v);
    }

    @Override
    public String toString() {
        return "EthSignature(rLow=" + rLow + ", rHigh=" + rHigh
            + ", sLow=" + sLow + ", sHigh=" + sHigh + ", v=" + v + ")";
    }
}
