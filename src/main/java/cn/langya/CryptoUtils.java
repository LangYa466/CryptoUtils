package cn.langya;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Objects;

/**
 * Provides utility methods for various cryptographic operations including
 * symmetric encryption (AES-GCM, AES-CBC, ChaCha20-Poly1305, DES-CBC),
 * asymmetric encryption (RSA), password-based key derivation (PBKDF2),
 * hashing for integrity (HMAC-SHA256), and a classical cipher (Caesar).
 *
 * @author LangYa466
 * @since 2024-07-27 // Updated Date
 */
public class CryptoUtils {

    // --- Algorithm Constants ---
    private static final String AES_ALGORITHM = "AES";
    private static final String AES_TRANSFORMATION_GCM = "AES/GCM/NoPadding";
    private static final String AES_TRANSFORMATION_CBC = "AES/CBC/PKCS5Padding";

    private static final String CHACHA20_ALGORITHM = "ChaCha20";
    // ChaCha20-Poly1305 is an AEAD cipher, transformation name might vary by provider
    // Standard names include "ChaCha20-Poly1305", "ChaCha20/Poly1305/NoPadding"
    private static final String CHACHA20_TRANSFORMATION = "ChaCha20-Poly1305";

    private static final String DES_ALGORITHM = "DES";
    private static final String DES_TRANSFORMATION = "DES/CBC/PKCS5Padding"; // DES is insecure

    private static final String RSA_ALGORITHM = "RSA";
    // Common RSA padding scheme. Others like OAEP are more secure.
    private static final String RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding";

    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String HMAC_ALGORITHM = "HmacSHA256";


    // --- Key & Parameter Size Constants ---
    public static final int AES_KEY_SIZE = 256; // bits
    private static final int GCM_IV_LENGTH = 12; // bytes (96 bits) - Recommended for GCM
    private static final int GCM_TAG_LENGTH = 16; // bytes (128 bits) - Recommended for GCM
    private static final int CBC_IV_LENGTH = 16; // bytes (128 bits) - AES block size

    public static final int CHACHA20_KEY_SIZE = 256; // bits
    private static final int CHACHA20_NONCE_LENGTH = 12; // bytes (96 bits) - Recommended for ChaCha20-Poly1305

    public static final int DES_KEY_SIZE = 56; // bits (effectively)
    private static final int DES_IV_LENGTH = 8; // bytes (64 bits) - DES block size

    public static final int RSA_KEY_SIZE = 2048; // bits - Common minimum size

    // --- Secure Random Instance ---
    private static final SecureRandom secureRandom = new SecureRandom();

    // --- Key Generation ---

    /**
     * Generates a secret key for AES encryption.
     * @return A SecretKey for AES.
     * @throws NoSuchAlgorithmException If AES algorithm is not available.
     */
    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGORITHM);
        keyGen.init(AES_KEY_SIZE, secureRandom);
        return keyGen.generateKey();
    }

    /**
     * Generates a secret key for DES encryption. (Note: DES is insecure).
     * @return A SecretKey for DES.
     * @throws NoSuchAlgorithmException If DES algorithm is not available.
     */
    public static SecretKey generateDESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(DES_ALGORITHM);
        // DES key size is effectively 56 bits, though it requires 64 bits (8 bytes) with parity.
        // KeyGenerator handles this.
        keyGen.init(DES_KEY_SIZE, secureRandom);
        return keyGen.generateKey();
    }

    /**
     * Generates a secret key for ChaCha20 encryption.
     * Requires Java 11+ or a provider like BouncyCastle.
     * @return A SecretKey for ChaCha20.
     * @throws NoSuchAlgorithmException If ChaCha20 algorithm is not available.
     */
    public static SecretKey generateChaCha20Key() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(CHACHA20_ALGORITHM);
        keyGen.init(CHACHA20_KEY_SIZE, secureRandom);
        return keyGen.generateKey();
    }

    /**
     * Generates a public/private key pair for RSA encryption/decryption.
     * @return A KeyPair containing the RSA public and private keys.
     * @throws NoSuchAlgorithmException If RSA algorithm is not available.
     */
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyGen.initialize(RSA_KEY_SIZE, secureRandom);
        return keyGen.generateKeyPair();
    }


    /**
     * Derives a secret key from a password and salt using PBKDF2.
     *
     * @param password The password to use.
     * @param salt A unique salt (byte array recommended, but string used for simplicity here).
     * @param algorithm The target algorithm for the derived key (e.g., "AES", "DES").
     * @param keySize The desired key size in bits.
     * @return The derived SecretKey.
     * @throws NoSuchAlgorithmException If PBKDF2WithHmacSHA256 is not available.
     * @throws InvalidKeySpecException If the key specification is invalid.
     */
    public static SecretKey getKeyFromPassword(String password, String salt, String algorithm, int keySize)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        // Use a high iteration count (e.g., 65536 or more)
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(StandardCharsets.UTF_8), 65536, keySize);
        // Generate the secret key bytes using PBKDF2
        SecretKey tmp = factory.generateSecret(spec);
        // Create a SecretKeySpec suitable for the target algorithm (AES, DES, etc.)
        return new SecretKeySpec(tmp.getEncoded(), algorithm);
    }


    // --- IV/Nonce Generation ---

    /**
     * Generates a random Initialization Vector (IV) or Nonce.
     * @param length The desired length in bytes.
     * @return The generated byte array.
     */
    public static byte[] generateIv(int length) {
        byte[] iv = new byte[length];
        secureRandom.nextBytes(iv);
        return iv;
    }

    // --- AES-GCM Encryption/Decryption (AEAD - Recommended) ---

    /**
     * Encrypts plaintext using AES-GCM. Prepends the IV to the ciphertext.
     * AEAD mode provides both confidentiality and integrity.
     *
     * @param plainText The text to encrypt.
     * @param key The AES secret key.
     * @return Base64 encoded string containing [IV + Ciphertext + AuthTag].
     * @throws Exception If encryption fails.
     */
    public static String encryptAES_GCM(String plainText, SecretKey key) throws Exception {
        byte[] iv = generateIv(GCM_IV_LENGTH);
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION_GCM);
        // GCMParameterSpec: tag length in bits, IV bytes
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        // Prepend IV to ciphertext for transmission/storage
        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + cipherText.length);
        byteBuffer.put(iv);
        byteBuffer.put(cipherText);
        return Base64.getEncoder().encodeToString(byteBuffer.array());
    }

    /**
     * Decrypts AES-GCM ciphertext. Assumes IV is prepended to the ciphertext.
     * Verifies the integrity tag during decryption.
     *
     * @param cipherTextWithIv Base64 encoded string containing [IV + Ciphertext + AuthTag].
     * @param key The AES secret key.
     * @return The original plaintext.
     * @throws Exception If decryption or integrity verification fails.
     */
    public static String decryptAES_GCM(String cipherTextWithIv, SecretKey key) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(cipherTextWithIv);
        ByteBuffer byteBuffer = ByteBuffer.wrap(decoded);

        // Extract IV
        byte[] iv = new byte[GCM_IV_LENGTH];
        byteBuffer.get(iv);

        // Extract Ciphertext (includes the authentication tag)
        byte[] cipherText = new byte[byteBuffer.remaining()];
        byteBuffer.get(cipherText);

        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION_GCM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
        byte[] plainText = cipher.doFinal(cipherText); // Throws AEADBadTagException if integrity check fails
        return new String(plainText, StandardCharsets.UTF_8);
    }

    // --- AES-CBC Encryption/Decryption (Requires separate integrity check like HMAC) ---

    /**
     * Encrypts plaintext using AES-CBC. Prepends the IV to the ciphertext.
     * Note: CBC mode requires padding (PKCS5Padding used here) and does not
     * provide integrity protection on its own. Use HMAC alongside it if needed.
     *
     * @param plainText The text to encrypt.
     * @param key The AES secret key.
     * @return Base64 encoded string containing [IV + Ciphertext].
     * @throws Exception If encryption fails.
     */
    public static String encryptAES_CBC(String plainText, SecretKey key) throws Exception {
        byte[] iv = generateIv(CBC_IV_LENGTH);
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION_CBC);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        // Prepend IV
        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + cipherText.length);
        byteBuffer.put(iv);
        byteBuffer.put(cipherText);
        return Base64.getEncoder().encodeToString(byteBuffer.array());
    }

    /**
     * Decrypts AES-CBC ciphertext. Assumes IV is prepended.
     *
     * @param cipherTextWithIv Base64 encoded string containing [IV + Ciphertext].
     * @param key The AES secret key.
     * @return The original plaintext.
     * @throws Exception If decryption fails (e.g., BadPaddingException).
     */
    public static String decryptAES_CBC(String cipherTextWithIv, SecretKey key) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(cipherTextWithIv);
        ByteBuffer byteBuffer = ByteBuffer.wrap(decoded);

        // Extract IV
        byte[] iv = new byte[CBC_IV_LENGTH];
        byteBuffer.get(iv);

        // Extract Ciphertext
        byte[] cipherText = new byte[byteBuffer.remaining()];
        byteBuffer.get(cipherText);

        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION_CBC);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        byte[] plainText = cipher.doFinal(cipherText);
        return new String(plainText, StandardCharsets.UTF_8);
    }

    // --- ChaCha20-Poly1305 Encryption/Decryption (AEAD - Recommended, Requires Java 11+) ---

    /**
     * Encrypts plaintext using ChaCha20-Poly1305. Prepends the nonce.
     * AEAD mode provides both confidentiality and integrity. Requires Java 11+.
     *
     * @param plainText The text to encrypt.
     * @param key The ChaCha20 secret key.
     * @return Base64 encoded string containing [Nonce + Ciphertext + AuthTag].
     * @throws Exception If encryption fails or the algorithm is unavailable.
     */
    public static String encryptChaCha20(String plainText, SecretKey key) throws Exception {
        byte[] nonce = generateIv(CHACHA20_NONCE_LENGTH); // Nonce for ChaCha20
        Cipher cipher = Cipher.getInstance(CHACHA20_TRANSFORMATION);
        // GCMParameterSpec can be used for ChaCha20 nonces as well
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        // Prepend Nonce
        ByteBuffer byteBuffer = ByteBuffer.allocate(nonce.length + cipherText.length);
        byteBuffer.put(nonce);
        byteBuffer.put(cipherText);
        return Base64.getEncoder().encodeToString(byteBuffer.array());
    }

    /**
     * Decrypts ChaCha20-Poly1305 ciphertext. Assumes nonce is prepended.
     * Verifies the integrity tag during decryption. Requires Java 11+.
     *
     * @param cipherTextWithNonce Base64 encoded string containing [Nonce + Ciphertext + AuthTag].
     * @param key The ChaCha20 secret key.
     * @return The original plaintext.
     * @throws Exception If decryption fails, integrity check fails, or the algorithm is unavailable.
     */
    public static String decryptChaCha20(String cipherTextWithNonce, SecretKey key) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(cipherTextWithNonce);
        ByteBuffer byteBuffer = ByteBuffer.wrap(decoded);

        // Extract Nonce
        byte[] nonce = new byte[CHACHA20_NONCE_LENGTH];
        byteBuffer.get(nonce);

        // Extract Ciphertext (includes the authentication tag)
        byte[] cipherText = new byte[byteBuffer.remaining()];
        byteBuffer.get(cipherText);

        Cipher cipher = Cipher.getInstance(CHACHA20_TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
        byte[] plainText = cipher.doFinal(cipherText); // Throws AEADBadTagException if integrity check fails
        return new String(plainText, StandardCharsets.UTF_8);
    }


    // --- DES-CBC Encryption/Decryption (Insecure - Avoid Use) ---

    /**
     * Encrypts plaintext using DES-CBC. Prepends the IV.
     * WARNING: DES is considered insecure due to its small key size (56-bit). Avoid using it.
     *
     * @param plainText The text to encrypt.
     * @param key The DES secret key.
     * @return Base64 encoded string containing [IV + Ciphertext].
     * @throws Exception If encryption fails.
     */
    public static String encryptDES_CBC(String plainText, SecretKey key) throws Exception {
        byte[] iv = generateIv(DES_IV_LENGTH);
        Cipher cipher = Cipher.getInstance(DES_TRANSFORMATION);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        // Prepend IV
        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + cipherText.length);
        byteBuffer.put(iv);
        byteBuffer.put(cipherText);
        return Base64.getEncoder().encodeToString(byteBuffer.array());
    }

    /**
     * Decrypts DES-CBC ciphertext. Assumes IV is prepended.
     * WARNING: Related to the insecure DES algorithm.
     *
     * @param cipherTextWithIv Base64 encoded string containing [IV + Ciphertext].
     * @param key The DES secret key.
     * @return The original plaintext.
     * @throws Exception If decryption fails.
     */
    public static String decryptDES_CBC(String cipherTextWithIv, SecretKey key) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(cipherTextWithIv);
        ByteBuffer byteBuffer = ByteBuffer.wrap(decoded);

        // Extract IV
        byte[] iv = new byte[DES_IV_LENGTH];
        byteBuffer.get(iv);

        // Extract Ciphertext
        byte[] cipherText = new byte[byteBuffer.remaining()];
        byteBuffer.get(cipherText);

        Cipher cipher = Cipher.getInstance(DES_TRANSFORMATION);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        byte[] plainText = cipher.doFinal(cipherText);
        return new String(plainText, StandardCharsets.UTF_8);
    }


    // --- RSA Asymmetric Encryption/Decryption ---

    /**
     * Encrypts data using an RSA public key.
     * Typically used for small data like encrypting symmetric keys.
     *
     * @param plainText The text to encrypt.
     * @param publicKey The RSA public key.
     * @return Base64 encoded ciphertext.
     * @throws Exception If encryption fails.
     */
    public static String encryptRSA(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(cipherText);
    }

    /**
     * Decrypts data using an RSA private key.
     *
     * @param cipherTextBase64 Base64 encoded ciphertext.
     * @param privateKey The RSA private key.
     * @return The original plaintext.
     * @throws Exception If decryption fails.
     */
    public static String decryptRSA(String cipherTextBase64, PrivateKey privateKey) throws Exception {
        byte[] cipherText = Base64.getDecoder().decode(cipherTextBase64);
        Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] plainText = cipher.doFinal(cipherText);
        return new String(plainText, StandardCharsets.UTF_8);
    }

    // --- HMAC (Hash-based Message Authentication Code) for Integrity ---

    /**
     * Calculates the HMAC-SHA256 for given data using a secret key.
     * Provides integrity and authenticity verification. Does not encrypt.
     *
     * @param data The data to calculate the HMAC for.
     * @param key The secret key (e.g., an AES key can be used, or a dedicated HMAC key).
     * @return Base64 encoded HMAC value.
     * @throws Exception If HMAC calculation fails.
     */
    public static String calculateHMAC(String data, SecretKey key) throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(key);
        byte[] hmacBytes = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hmacBytes);
    }

    /**
     * Verifies an HMAC-SHA256 value for given data and key.
     * Uses a constant-time comparison to prevent timing attacks.
     *
     * @param data The data that was supposedly MAC'd.
     * @param key The secret key used for the original HMAC.
     * @param hmacToVerifyBase64 The Base64 encoded HMAC value received.
     * @return True if the calculated HMAC matches the provided one, false otherwise.
     * @throws Exception If HMAC calculation fails during verification.
     */
    public static boolean verifyHMAC(String data, SecretKey key, String hmacToVerifyBase64) throws Exception {
        String calculatedHmacBase64 = calculateHMAC(data, key);
        // Decode both HMACs to byte arrays for constant-time comparison
        byte[] calculatedHmac = Base64.getDecoder().decode(calculatedHmacBase64);
        byte[] hmacToVerify = Base64.getDecoder().decode(hmacToVerifyBase64);

        // Use MessageDigest.isEqual for constant-time comparison
        return MessageDigest.isEqual(calculatedHmac, hmacToVerify);
    }

    // --- Caesar Cipher (Classical - Insecure) ---

    /**
     * Encrypts text using a Caesar cipher with a given shift.
     * Only shifts uppercase and lowercase English alphabet letters. Preserves case.
     * WARNING: This is a classical cipher and completely insecure for modern use.
     *
     * @param plainText The text to encrypt.
     * @param shift The number of positions to shift letters (can be positive or negative).
     * @return The Caesar-encrypted text.
     */
    public static String encryptCaesar(String plainText, int shift) {
        StringBuilder cipherText = new StringBuilder();
        for (char character : plainText.toCharArray()) {
            if (Character.isLetter(character)) {
                char base = Character.isUpperCase(character) ? 'A' : 'a';
                // Calculate shifted character with wrap-around using modulo
                char shifted = (char) (base + (character - base + shift % 26 + 26) % 26);
                cipherText.append(shifted);
            } else {
                // Keep non-alphabetic characters as they are
                cipherText.append(character);
            }
        }
        return cipherText.toString();
    }

    /**
     * Decrypts text encrypted with a Caesar cipher using the same shift.
     * WARNING: Related to the insecure Caesar cipher.
     *
     * @param cipherText The Caesar-encrypted text.
     * @param shift The original shift used for encryption.
     * @return The decrypted text.
     */
    public static String decryptCaesar(String cipherText, int shift) {
        // Decryption is just encryption with the opposite shift
        return encryptCaesar(cipherText, -shift);
    }


    // --- Base64 Helper Methods ---

    /**
     * Encodes byte array to Base64 string.
     * @param data The byte array to encode.
     * @return The Base64 encoded string.
     */
    public static String encodeBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    /**
     * Decodes Base64 string to byte array.
     * @param data The Base64 encoded string.
     * @return The decoded byte array.
     */
    public static byte[] decodeBase64(String data) {
        return Base64.getDecoder().decode(data);
    }
}