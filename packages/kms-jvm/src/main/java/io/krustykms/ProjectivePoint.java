package io.krustykms;

import java.util.Objects;

public final class ProjectivePoint {
    private final Felt x;
    private final Felt y;
    private final Felt z;

    public ProjectivePoint(Felt x, Felt y, Felt z) {
        this.x = Objects.requireNonNull(x);
        this.y = Objects.requireNonNull(y);
        this.z = Objects.requireNonNull(z);
    }

    public Felt x() { return x; }
    public Felt y() { return y; }
    public Felt z() { return z; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ProjectivePoint)) return false;
        ProjectivePoint that = (ProjectivePoint) o;
        return x.equals(that.x) && y.equals(that.y) && z.equals(that.z);
    }

    @Override
    public int hashCode() {
        return Objects.hash(x, y, z);
    }

    @Override
    public String toString() {
        return "ProjectivePoint(x=" + x + ", y=" + y + ", z=" + z + ")";
    }
}
