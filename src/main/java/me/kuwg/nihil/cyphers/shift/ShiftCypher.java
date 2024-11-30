package me.kuwg.nihil.cyphers.shift;

import me.kuwg.nihil.cypher.NihilCypher;
import me.kuwg.nihil.cypher.NihilKey;

import java.nio.ByteBuffer;

public class ShiftCypher extends NihilCypher {
    public ShiftCypher(final NihilKey key) {
        super(key);
    }

    @Override
    public byte[] encrypt(final byte[] bytes) {
        final byte[] keyBytes = key.getBytes();
        final byte[] encrypted = new byte[bytes.length];

        for (int i = 0; i < bytes.length; i++) {
            final int shift = keyBytes[i % keyBytes.length];
            final int shifted = (bytes[i] + shift) & 0xFF;
            encrypted[i] = (byte) shifted;
        }

        return encrypted;
    }

    @Override
    public <T> T decrypt(final byte[] encryptedData, final Class<T> type) {
        final byte[] keyBytes = key.getBytes();
        final byte[] decrypted = new byte[encryptedData.length];

        for (int i = 0; i < encryptedData.length; i++) {
            final int shift = keyBytes[i % keyBytes.length];
            final int shiftedBack = (encryptedData[i] - shift) & 0xFF;
            decrypted[i] = (byte) shiftedBack;

        }

        final ByteBuffer buffer = ByteBuffer.wrap(decrypted);
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
        }  else {
            throw new IllegalArgumentException("Unsupported type for decryption: " + type.getName());
        }
    }
}
