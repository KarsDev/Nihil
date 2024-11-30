package me.kuwg.nihil.cyphers.dshift;

import me.kuwg.nihil.cypher.NihilCypher;
import me.kuwg.nihil.cypher.NihilKey;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class SecureDoubleShiftCypher extends NihilCypher {
    private static final int SALT_LENGTH = 16;
    private static final int HMAC_LENGTH = 32;
    private static final String HMAC_ALGORITHM = "HmacSHA256";

    public SecureDoubleShiftCypher(final NihilKey key) {
        super(key);
    }

    @Override
    public byte[] encrypt(final byte[] bytes) throws RuntimeException {
        final SecureRandom rnd = new SecureRandom();
        final byte[] keyBytes = deriveKey(key.getBytes());
        final byte[] salt = new byte[SALT_LENGTH];
        rnd.nextBytes(salt);

        final byte[] encrypted = new byte[bytes.length * 2 + SALT_LENGTH];
        System.arraycopy(salt, 0, encrypted, 0, SALT_LENGTH);

        for (int i = 0, j = SALT_LENGTH; i < bytes.length; i++, j += 2) {
            final byte randShift = (byte) rnd.nextInt(256);
            final byte keyShift = (byte) (i % keyBytes.length);
            encrypted[j] = randShift;
            encrypted[j + 1] = (byte) ((bytes[i] ^ randShift) ^ keyBytes[keyShift]);
        }

        // Add HMAC for integrity
        byte[] hmac = generateHMAC(encrypted, keyBytes);
        byte[] result = new byte[encrypted.length + HMAC_LENGTH];
        System.arraycopy(encrypted, 0, result, 0, encrypted.length);
        System.arraycopy(hmac, 0, result, encrypted.length, HMAC_LENGTH);

        return result;
    }

    @Override
    public <T> T decrypt(final byte[] encryptedData, final Class<T> type) throws RuntimeException {
        if (encryptedData.length <= SALT_LENGTH + HMAC_LENGTH) {
            throw new IllegalArgumentException("Invalid encrypted data length");
        }

        final byte[] keyBytes = deriveKey(key.getBytes());
        final byte[] hmac = Arrays.copyOfRange(encryptedData, encryptedData.length - HMAC_LENGTH, encryptedData.length);
        final byte[] dataWithoutHmac = Arrays.copyOfRange(encryptedData, 0, encryptedData.length - HMAC_LENGTH);

        // Verify HMAC integrity
        byte[] calculatedHmac = generateHMAC(dataWithoutHmac, keyBytes);
        if (!MessageDigest.isEqual(hmac, calculatedHmac)) {
            throw new SecurityException("Invalid HMAC, data integrity compromised");
        }

        final byte[] salt = Arrays.copyOfRange(dataWithoutHmac, 0, SALT_LENGTH);
        final byte[] encrypted = Arrays.copyOfRange(dataWithoutHmac, SALT_LENGTH, dataWithoutHmac.length);

        final byte[] decrypted = new byte[encrypted.length / 2];
        for (int i = 0, j = 0; i < decrypted.length; i++, j += 2) {
            final byte randShift = encrypted[j];
            final byte encryptedByte = encrypted[j + 1];
            final byte keyShift = (byte) (i % keyBytes.length);
            decrypted[i] = (byte) ((encryptedByte ^ randShift) ^ keyBytes[keyShift]);
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
        } else {
            throw new IllegalArgumentException("Unsupported type for decryption: " + type.getName());
        }
    }

    private byte[] deriveKey(final byte[] keyBytes) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(keyBytes);
        } catch (Exception e) {
            throw new RuntimeException("Failed to derive key", e);
        }
    }

    private byte[] generateHMAC(byte[] data, byte[] key) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(key, HMAC_ALGORITHM);
            mac.init(keySpec);
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate HMAC", e);
        }
    }
}
