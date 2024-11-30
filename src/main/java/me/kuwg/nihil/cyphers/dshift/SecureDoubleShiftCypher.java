package me.kuwg.nihil.cyphers.dshift;

import me.kuwg.nihil.cypher.NihilCypher;
import me.kuwg.nihil.cypher.NihilKey;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Random;

public class DoubleShiftCypher extends NihilCypher {
    public DoubleShiftCypher(final NihilKey key) {
        super(key);
    }

    @Override
    public byte[] encrypt(final byte[] bytes) throws RuntimeException {
        final byte[] keyBytes = key.getBytes();
        final byte[] encrypted = new byte[bytes.length * 3];

        final Random rnd = new SecureRandom();

        for (int i = 0, j = 0; i < bytes.length; i++, j += 3) {
            final byte randShift = (byte) rnd.nextInt(256);
            final byte keyShift = (byte) (i % keyBytes.length);
            encrypted[j] = randShift;
            encrypted[j + 1] = keyShift;
            encrypted[j + 2] = (byte) ((bytes[i] ^ randShift) ^ keyBytes[keyShift]);
        }

        return encrypted;
    }

    @Override
    public <T> T decrypt(final byte[] encryptedData, final Class<T> type) throws RuntimeException {
        if (encryptedData.length % 3 != 0) {
            throw new IllegalArgumentException("Invalid encrypted data length");
        }

        final byte[] keyBytes = key.getBytes();
        final byte[] decrypted = new byte[encryptedData.length / 3];

        for (int i = 0, j = 0; i < decrypted.length; i++, j += 3) {
            final byte randShift = encryptedData[j];
            final byte keyShift = encryptedData[j + 1];
            decrypted[i] = (byte) ((encryptedData[j + 2] ^ randShift) ^ keyBytes[keyShift]);
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
        } else {
            throw new IllegalArgumentException("Unsupported type for decryption: " + type.getName());
        }
    }
}