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

        return superCast(decrypted, type, ByteBuffer.wrap(decrypted));
    }
}
