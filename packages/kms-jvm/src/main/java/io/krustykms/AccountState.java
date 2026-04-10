package io.krustykms;

import java.util.Objects;

public final class AccountState {
    private final long balanceLow;
    private final long balanceHigh;
    private final long pendingBalanceLow;
    private final long pendingBalanceHigh;
    private final long nonce;

    public AccountState(long balanceLow, long balanceHigh,
                        long pendingBalanceLow, long pendingBalanceHigh,
                        long nonce) {
        this.balanceLow = balanceLow;
        this.balanceHigh = balanceHigh;
        this.pendingBalanceLow = pendingBalanceLow;
        this.pendingBalanceHigh = pendingBalanceHigh;
        this.nonce = nonce;
    }

    public long balanceLow() { return balanceLow; }
    public long balanceHigh() { return balanceHigh; }
    public long pendingBalanceLow() { return pendingBalanceLow; }
    public long pendingBalanceHigh() { return pendingBalanceHigh; }
    public long nonce() { return nonce; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AccountState)) return false;
        AccountState that = (AccountState) o;
        return balanceLow == that.balanceLow
            && balanceHigh == that.balanceHigh
            && pendingBalanceLow == that.pendingBalanceLow
            && pendingBalanceHigh == that.pendingBalanceHigh
            && nonce == that.nonce;
    }

    @Override
    public int hashCode() {
        return Objects.hash(balanceLow, balanceHigh, pendingBalanceLow, pendingBalanceHigh, nonce);
    }

    @Override
    public String toString() {
        return "AccountState(balanceLow=" + balanceLow
            + ", balanceHigh=" + balanceHigh
            + ", pendingBalanceLow=" + pendingBalanceLow
            + ", pendingBalanceHigh=" + pendingBalanceHigh
            + ", nonce=" + nonce + ")";
    }
}
