package io.krustykms;

public final class AccountHandle {
    private final long rawValue;

    public AccountHandle(long rawValue) {
        this.rawValue = rawValue;
    }

    public long rawValue() {
        return rawValue;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AccountHandle)) return false;
        return rawValue == ((AccountHandle) o).rawValue;
    }

    @Override
    public int hashCode() {
        return Long.hashCode(rawValue);
    }

    @Override
    public String toString() {
        return "AccountHandle(" + rawValue + ")";
    }
}
