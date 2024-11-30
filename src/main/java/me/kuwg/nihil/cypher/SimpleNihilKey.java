package me.kuwg.nihil.cypher;

import java.security.SecureRandom;

public final class SimpleNihilKey extends NihilKey {
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public SimpleNihilKey(final int... bytes) {
        super(proc(bytes));
    }

    public SimpleNihilKey(final byte... bytes) {
        super(bytes);
    }

    @Override
    public Object clone() {
        return new SimpleNihilKey(bytes.clone());
    }

    public static SimpleNihilKey random(int size) {
        if (size <= 0) {
            throw new IllegalArgumentException("Size must be positive.");
        }
        byte[] randomBytes = new byte[size];
        SECURE_RANDOM.nextBytes(randomBytes);
        return new SimpleNihilKey(randomBytes);
    }

    private static byte[] proc(final int[] ints) {
        final byte[] bytes = new byte[ints.length];

        for (int i = 0; i < ints.length; i++) {
            bytes[i] = (byte) ints[i];
        }

        return bytes;
    }
}