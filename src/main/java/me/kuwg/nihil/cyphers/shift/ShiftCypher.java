package me.kuwg.nihil.cypher;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class ShiftCypher extends NihilCypher {

    public ShiftCypher(final NihilKey key) {
        super(key);
    }

    @Override
    public byte[] encrypt(final byte[] bytes) {
        byte[] keyBytes = key.getBytes();
        byte[] encrypted = new byte[bytes.length];
        List<String> logs = new ArrayList<>();

        for (int i = 0; i < bytes.length; i++) {
            int shift = keyBytes[i % keyBytes.length]; // Cyclic use of the key
            int shifted = (bytes[i] + shift) & 0xFF; // Byte overflow handling
            encrypted[i] = (byte) shifted;

            logs.add("Byte: " + bytes[i] + ", Shift: " + shift + ", Result: " + shifted);
        }

        logs.forEach(System.out::println);
        return encrypted;
    }

    @Override
    public <T> T decrypt(final byte[] encryptedData, final Class<T> type) {
        byte[] keyBytes = key.getBytes();
        byte[] decrypted = new byte[encryptedData.length];
        List<String> logs = new ArrayList<>();

        for (int i = 0; i < encryptedData.length; i++) {
            int shift = keyBytes[i % keyBytes.length];
            int shiftedBack = (encryptedData[i] - shift) & 0xFF; // Byte overflow handling
            decrypted[i] = (byte) shiftedBack;

            logs.add("Encrypted Byte: " + encryptedData[i] + ", Shift: " + shift + ", Result: " + shiftedBack);
        }

        logs.forEach(System.out::println);

        // Convert back to the original data type
        ByteBuffer buffer = ByteBuffer.wrap(decrypted);
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
