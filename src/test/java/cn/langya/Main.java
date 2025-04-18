package cn.langya;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Main {

    public static void main(String[] args) {
        try {
            String originalText = "This is a secret message for testing purposes. 123!@# Test.";
            System.out.println("Original Text: " + originalText);
            System.out.println("========================================");
            System.out.println(" SYMMETRIC ENCRYPTION (Shared Key)");
            System.out.println("========================================");

            // --- AES-GCM Test (Recommended AEAD) ---
            System.out.println("Testing AES-GCM (" + CryptoUtils.AES_KEY_SIZE + " bits)...");
            SecretKey aesKeyGCM = CryptoUtils.generateAESKey();
            System.out.println("Generated AES Key (Base64): " + CryptoUtils.encodeBase64(aesKeyGCM.getEncoded()));
            String encryptedAES_GCM = CryptoUtils.encryptAES_GCM(originalText, aesKeyGCM);
            System.out.println("AES-GCM Encrypted (Base64): " + encryptedAES_GCM);
            String decryptedAES_GCM = CryptoUtils.decryptAES_GCM(encryptedAES_GCM, aesKeyGCM);
            System.out.println("AES-GCM Decrypted: " + decryptedAES_GCM);
            System.out.println("AES-GCM Verification: " + originalText.equals(decryptedAES_GCM));
            System.out.println("----------------------------------------");

            // --- AES-CBC Test (Needs separate integrity like HMAC) ---
            System.out.println("Testing AES-CBC (" + CryptoUtils.AES_KEY_SIZE + " bits)...");
            SecretKey aesKeyCBC = CryptoUtils.generateAESKey(); // Can reuse key or generate new one
            // SecretKey aesKeyCBC = aesKeyGCM; // Or reuse the same key
            System.out.println("Generated AES Key (Base64): " + CryptoUtils.encodeBase64(aesKeyCBC.getEncoded()));
            String encryptedAES_CBC = CryptoUtils.encryptAES_CBC(originalText, aesKeyCBC);
            System.out.println("AES-CBC Encrypted (Base64): " + encryptedAES_CBC);
            String decryptedAES_CBC = CryptoUtils.decryptAES_CBC(encryptedAES_CBC, aesKeyCBC);
            System.out.println("AES-CBC Decrypted: " + decryptedAES_CBC);
            System.out.println("AES-CBC Verification: " + originalText.equals(decryptedAES_CBC));
            System.out.println("----------------------------------------");


            // --- ChaCha20-Poly1305 Test (Recommended AEAD, Requires Java 11+) ---
            System.out.println("Testing ChaCha20-Poly1305 (" + CryptoUtils.CHACHA20_KEY_SIZE + " bits)...");
            try {
                SecretKey chachaKey = CryptoUtils.generateChaCha20Key();
                System.out.println("Generated ChaCha20 Key (Base64): " + CryptoUtils.encodeBase64(chachaKey.getEncoded()));
                String encryptedChaCha20 = CryptoUtils.encryptChaCha20(originalText, chachaKey);
                System.out.println("ChaCha20 Encrypted (Base64): " + encryptedChaCha20);
                String decryptedChaCha20 = CryptoUtils.decryptChaCha20(encryptedChaCha20, chachaKey);
                System.out.println("ChaCha20 Decrypted: " + decryptedChaCha20);
                System.out.println("ChaCha20 Verification: " + originalText.equals(decryptedChaCha20));
            } catch (NoSuchAlgorithmException e) {
                System.out.println("ChaCha20-Poly1305 algorithm not available. Requires Java 11 or higher, or a provider like BouncyCastle.");
            } catch (Exception e) {
                System.err.println("ChaCha20 Error: " + e.getMessage());
                // e.printStackTrace(); // Optionally print stack trace for debugging
            }
            System.out.println("----------------------------------------");

            // --- DES-CBC Test (Insecure - For Demonstration Only) ---
            System.out.println("Testing DES-CBC (" + CryptoUtils.DES_KEY_SIZE + " bits)... (Warning: DES is insecure!)");
            SecretKey desKey = CryptoUtils.generateDESKey();
            System.out.println("Generated DES Key (Base64): " + CryptoUtils.encodeBase64(desKey.getEncoded()));
            String encryptedDES = CryptoUtils.encryptDES_CBC(originalText, desKey);
            System.out.println("DES Encrypted (Base64): " + encryptedDES);
            String decryptedDES = CryptoUtils.decryptDES_CBC(encryptedDES, desKey);
            System.out.println("DES Decrypted: " + decryptedDES);
            System.out.println("DES Verification: " + originalText.equals(decryptedDES));
            System.out.println("----------------------------------------");

            // --- Password Based Key Derivation Example (Using AES-GCM) ---
            System.out.println("Testing Password Based Encryption (PBKDF2 + AES-GCM)...");
            String password = "VerySecretPassword123";
            // IMPORTANT: Use a unique, cryptographically secure random salt for each user/operation in production.
            // Store the salt alongside the ciphertext.
            String salt = "UniqueSaltForEachUserOrOperation"; // Example salt
            SecretKey derivedKey = CryptoUtils.getKeyFromPassword(password, salt, "AES", CryptoUtils.AES_KEY_SIZE);
            System.out.println("Derived AES Key from Password (Base64): " + CryptoUtils.encodeBase64(derivedKey.getEncoded()));
            String encryptedPBE = CryptoUtils.encryptAES_GCM(originalText, derivedKey);
            System.out.println("PBE AES-GCM Encrypted (Base64): " + encryptedPBE);
            // To decrypt, you need the same password, salt, and ciphertext
            SecretKey derivedKeyForDecrypt = CryptoUtils.getKeyFromPassword(password, salt, "AES", CryptoUtils.AES_KEY_SIZE);
            String decryptedPBE = CryptoUtils.decryptAES_GCM(encryptedPBE, derivedKeyForDecrypt);
            System.out.println("PBE AES-GCM Decrypted: " + decryptedPBE);
            System.out.println("PBE AES-GCM Verification: " + originalText.equals(decryptedPBE));
            System.out.println("----------------------------------------");

            System.out.println("\n========================================");
            System.out.println(" ASYMMETRIC ENCRYPTION (Public/Private Key)");
            System.out.println("========================================");

            // --- RSA Test ---
            System.out.println("Testing RSA (" + CryptoUtils.RSA_KEY_SIZE + " bits)...");
            KeyPair rsaKeyPair = CryptoUtils.generateRSAKeyPair();
            PublicKey rsaPublicKey = rsaKeyPair.getPublic();
            PrivateKey rsaPrivateKey = rsaKeyPair.getPrivate();
            System.out.println("Generated RSA Public Key (Base64): " + CryptoUtils.encodeBase64(rsaPublicKey.getEncoded()));
            // Private key is usually kept secret, only showing format here
            System.out.println("Generated RSA Private Key (Format): " + rsaPrivateKey.getFormat());

            // Note: RSA is usually used for small data (like encrypting a symmetric key)
            String rsaEncrypted = CryptoUtils.encryptRSA(originalText, rsaPublicKey);
            System.out.println("RSA Encrypted (Base64): " + rsaEncrypted);
            String rsaDecrypted = CryptoUtils.decryptRSA(rsaEncrypted, rsaPrivateKey);
            System.out.println("RSA Decrypted: " + rsaDecrypted);
            System.out.println("RSA Verification: " + originalText.equals(rsaDecrypted));
            System.out.println("----------------------------------------");

            System.out.println("\n========================================");
            System.out.println(" MESSAGE INTEGRITY & AUTHENTICITY");
            System.out.println("========================================");

            // --- HMAC-SHA256 Test ---
            System.out.println("Testing HMAC-SHA256...");
            // Can use a dedicated key or reuse an existing symmetric key (like AES)
            SecretKey hmacKey = CryptoUtils.generateAESKey(); // Using an AES key for HMAC example
            System.out.println("Generated HMAC Key (Base64): " + CryptoUtils.encodeBase64(hmacKey.getEncoded()));

            String calculatedHMAC = CryptoUtils.calculateHMAC(originalText, hmacKey);
            System.out.println("Calculated HMAC (Base64): " + calculatedHMAC);

            // Verification - Simulate checking received data and HMAC
            boolean isValid = CryptoUtils.verifyHMAC(originalText, hmacKey, calculatedHMAC);
            System.out.println("HMAC Verification (Original Data): " + isValid);

            // Verification - Simulate tampered data
            String tamperedText = originalText + " (tampered)";
            boolean isTamperedValid = CryptoUtils.verifyHMAC(tamperedText, hmacKey, calculatedHMAC);
            System.out.println("HMAC Verification (Tampered Data): " + isTamperedValid);
            System.out.println("----------------------------------------");

            System.out.println("\n========================================");
            System.out.println(" CLASSICAL CIPHERS (Insecure)");
            System.out.println("========================================");

            // --- Caesar Cipher Test (Insecure) ---
            System.out.println("Testing Caesar Cipher... (Warning: Insecure!)");
            int caesarShift = 3;
            System.out.println("Caesar Shift: " + caesarShift);
            String encryptedCaesar = CryptoUtils.encryptCaesar(originalText, caesarShift);
            System.out.println("Caesar Encrypted: " + encryptedCaesar);
            String decryptedCaesar = CryptoUtils.decryptCaesar(encryptedCaesar, caesarShift);
            System.out.println("Caesar Decrypted: " + decryptedCaesar);
            System.out.println("Caesar Verification: " + originalText.equals(decryptedCaesar));
            System.out.println("----------------------------------------");


        } catch (Exception e) {
            System.err.println("\n!!! An error occurred during testing !!!");
            e.printStackTrace();
        }
    }
}