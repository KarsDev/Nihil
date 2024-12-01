package me.kuwg.nihil.cyphers.dshift;

import me.kuwg.nihil.cypher.NihilCypher;
import me.kuwg.nihil.cypher.NihilKey;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class SecureDoubleShiftCypher extends NihilCypher {
    private static final int SALT_LENGTH = 16;
    private static final int HMAC_LENGTH = 32;

    private static final String SHA_ALGORITHM = "SHA-256";
    private static final String HMAC_ALGORITHM = "HmacSHA256";

    public SecureDoubleShiftCypher(final NihilKey key) {
        super(key);
    }

    @Override
    public byte[] encrypt(final byte[] bytes) throws RuntimeException {
        final SecureRandom rnd = new SecureRandom();
        final byte[] result0;
        try {
            MessageDigest digest = MessageDigest.getInstance(SHA_ALGORITHM);
            result0 = digest.digest(key.getBytes());
        } catch (final Exception e) {
            throw new RuntimeException("Failed to derive key", e);
        }
        final byte[] salt = new byte[SALT_LENGTH];
        rnd.nextBytes(salt);

        final byte[] encrypted = new byte[bytes.length * 2 + SALT_LENGTH];
        System.arraycopy(salt, 0, encrypted, 0, SALT_LENGTH);

        for (int i = 0, j = SALT_LENGTH; i < bytes.length; i++, j += 2) {
            final byte randShift = (byte) rnd.nextInt(256);
            final byte keyShift = (byte) (i % result0.length);
            encrypted[j] = randShift;
            encrypted[j + 1] = (byte) ((bytes[i] ^ randShift) ^ result0[keyShift]);
        }

        final byte[] result1;
        try {
            final Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(result0, HMAC_ALGORITHM));
            result1 = mac.doFinal(encrypted);
        } catch (final InvalidKeyException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate HMAC", e);
        }
        final byte[] result = new byte[encrypted.length + HMAC_LENGTH];
        System.arraycopy(encrypted, 0, result, 0, encrypted.length);
        System.arraycopy(result1, 0, result, encrypted.length, HMAC_LENGTH);

        return result;
    }

    @Override
    public <T> T decrypt(final byte[] encryptedData, final Class<T> type) throws RuntimeException {
        if (encryptedData.length <= SALT_LENGTH + HMAC_LENGTH) {
            throw new IllegalArgumentException("Invalid encrypted data length");
        }

        final byte[] result0;
        try {
            result0 = MessageDigest.getInstance("SHA-256").digest(key.getBytes());
        } catch (final NoSuchAlgorithmException e1) {
            throw new RuntimeException("Failed to derive key", e1);
        }

        final byte[] keyBytes = result0;
        final byte[] hmac = Arrays.copyOfRange(encryptedData, encryptedData.length - HMAC_LENGTH, encryptedData.length);
        final byte[] dataWithoutHmac = Arrays.copyOfRange(encryptedData, 0, encryptedData.length - HMAC_LENGTH);

        final byte[] result1;
        try {
            final Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(keyBytes, HMAC_ALGORITHM));
            result1 = mac.doFinal(dataWithoutHmac);
        } catch (final InvalidKeyException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate HMAC", e);
        }

        if (!MessageDigest.isEqual(hmac, result1)) {
            throw new SecurityException("Invalid HMAC, data integrity compromised");
        }

        final byte[] encrypted = Arrays.copyOfRange(dataWithoutHmac, SALT_LENGTH, dataWithoutHmac.length);

        final byte[] decrypted = new byte[encrypted.length / 2];
        for (int i = 0, j = 0; i < decrypted.length; i++, j += 2) {
            final byte randShift = encrypted[j];
            final byte encryptedByte = encrypted[j + 1];
            final byte keyShift = (byte) (i % keyBytes.length);
            decrypted[i] = (byte) ((encryptedByte ^ randShift) ^ keyBytes[keyShift]);
        }

        return superCast(decrypted, type, ByteBuffer.wrap(decrypted));
    }

}
