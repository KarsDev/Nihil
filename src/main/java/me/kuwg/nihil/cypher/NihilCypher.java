package me.kuwg.nihil.cypher;

import java.nio.ByteBuffer;

public abstract class NihilCypher {
    protected final NihilKey key;

    protected NihilCypher(final NihilKey key) {
        this.key = key;
    }

    public final byte[] encrypt(final String i) {
        return encrypt(i.getBytes());
    }

    public final byte[] encrypt(final int i) {
        return encrypt(ByteBuffer.allocate(4).putInt(i).array());
    }

    public final byte[] encrypt(final double d) {
        return encrypt(ByteBuffer.allocate(8).putDouble(d).array());
    }

    public final byte[] encrypt(final short s) {
        return encrypt(ByteBuffer.allocate(2).putShort(s).array());
    }

    public final byte[] encrypt(final byte b) {
        return encrypt(new byte[]{b});
    }

    public final byte[] encrypt(final long l) {
        return encrypt(ByteBuffer.allocate(8).putLong(l).array());
    }

    public final byte[] encrypt(final float f) {
        return encrypt(ByteBuffer.allocate(4).putFloat(f).array());
    }

    public abstract byte[] encrypt(final byte[] bytes) throws RuntimeException;

    public abstract <T> T decrypt(final byte[] encryptedData, final Class<T> type) throws RuntimeException;

    public final NihilKey getKey() {
        return key;
    }

    protected final <T> T superCast(final byte[] decrypted, final Class<T> type, final ByteBuffer buffer) {
        if (type == Integer.class) {
            return type.cast(buffer.getInt());
        } else if (type == Double.class) {
            return type.cast(buffer.getDouble());
        } else if (type == Short.class) {
            return type.cast(buffer.getShort());
        } else if (type == Byte.class) {
            return type.cast(decrypted[0]);
        } else if (type == Long.class) {
            return type.cast(buffer.getLong());
        } else if (type == Float.class) {
            return type.cast(buffer.getFloat());
        } else if (type == String.class) {
            return type.cast(new String(decrypted));
        } else if (type == byte[].class) {
            return (T) decrypted;
        } else {
            throw new IllegalArgumentException("Unsupported type for decryption: " + type.getName());
        }
    }
}
