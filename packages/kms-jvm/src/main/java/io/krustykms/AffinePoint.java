package io.krustykms;

import java.util.Objects;

public final class AffinePoint {
    private final Felt x;
    private final Felt y;

    public AffinePoint(Felt x, Felt y) {
        this.x = Objects.requireNonNull(x);
        this.y = Objects.requireNonNull(y);
    }

    public Felt x() { return x; }
    public Felt y() { return y; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AffinePoint)) return false;
        AffinePoint that = (AffinePoint) o;
        return x.equals(that.x) && y.equals(that.y);
    }

    @Override
    public int hashCode() {
        return Objects.hash(x, y);
    }

    @Override
    public String toString() {
        return "AffinePoint(x=" + x + ", y=" + y + ")";
    }
}
