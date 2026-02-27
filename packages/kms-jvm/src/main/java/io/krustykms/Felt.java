package io.krustykms;

import java.util.Arrays;

public final class Felt {
    private final byte[] bytes;

    public Felt(byte[] bytes) {
        if (bytes.length != 32) {
            throw new IllegalArgumentException("Felt must be exactly 32 bytes, got " + bytes.length);
        }
        this.bytes = bytes.clone();
    }

    public byte[] bytes() {
        return bytes.clone();
    }

    public static Felt fromHex(String hex) {
        String h = hex;
        if (h.startsWith("0x") || h.startsWith("0X")) {
            h = h.substring(2);
        }
        if (h.length() % 2 != 0) {
            h = "0" + h;
        }
        byte[] raw = new byte[h.length() / 2];
        for (int i = 0; i < raw.length; i++) {
            raw[i] = (byte) Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16);
        }
        byte[] padded = new byte[32];
        System.arraycopy(raw, 0, padded, 32 - raw.length, raw.length);
        return new Felt(padded);
    }

    public String toHex() {
        StringBuilder sb = new StringBuilder("0x");
        boolean leading = true;
        for (byte b : bytes) {
            if (leading && b == 0) continue;
            leading = false;
            sb.append(String.format("%02x", b & 0xFF));
        }
        if (leading) sb.append('0');
        return sb.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Felt)) return false;
        return Arrays.equals(bytes, ((Felt) o).bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    @Override
    public String toString() {
        return "Felt(" + toHex() + ")";
    }
}
