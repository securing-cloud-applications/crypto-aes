package com.example.util;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.security.crypto.util.EncodingUtils;

public class CryptoUtils {

  private static final SecureRandom secureRandom = new SecureRandom();

  public static byte[] encryptAes256Gcm(byte[] clearText, String password, String salt) {
    try {
      Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
      GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, randomBytes(12));
      aes.init(Cipher.ENCRYPT_MODE, deriveKey(password, salt), gcmParameterSpec);
      byte[] cipherText = aes.doFinal(clearText);
      return EncodingUtils.concatenate(gcmParameterSpec.getIV(), cipherText);
    } catch (NoSuchAlgorithmException
        | NoSuchPaddingException
        | InvalidKeyException
        | InvalidAlgorithmParameterException
        | IllegalBlockSizeException
        | BadPaddingException e) {
      throw new RuntimeException(e);
    }
  }

  public static byte[] decryptAes256Gcm(byte[] cipherText, String password, String salt) {
    try {
      Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
      byte[] iv = EncodingUtils.subArray(cipherText, 0, 12);
      GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
      aes.init(Cipher.DECRYPT_MODE, deriveKey(password, salt), gcmParameterSpec);
      return aes.doFinal(EncodingUtils.subArray(cipherText, 12, cipherText.length));
    } catch (NoSuchAlgorithmException
        | NoSuchPaddingException
        | InvalidKeyException
        | InvalidAlgorithmParameterException
        | IllegalBlockSizeException
        | BadPaddingException e) {
      throw new RuntimeException(e);
    }
  }

  private static SecretKeySpec deriveKey(String password, String salt) {
    try {
      PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
      SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
      SecretKey derivedKey = keyFactory.generateSecret(keySpec);
      return new SecretKeySpec(derivedKey.getEncoded(), "AES");
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new RuntimeException(e);
    }
  }

  private static byte[] randomBytes(int amount) {
    byte[] iv = new byte[amount];
    secureRandom.nextBytes(iv);
    return iv;
  }
}
