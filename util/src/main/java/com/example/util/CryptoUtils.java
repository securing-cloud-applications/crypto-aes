package com.example.util;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.security.crypto.util.EncodingUtils;

public class CryptoUtils {

  private static final SecureRandom secureRandom = new SecureRandom();

  private static byte[] randomBytes(int amount) {
    byte[] iv = new byte[amount];
    secureRandom.nextBytes(iv);
    return iv;
  }

  public static byte[] encryptAes256Gcm(byte[] clearText, byte[] key) {
    try {
      Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");

      var gcmParameterSpec = new GCMParameterSpec(128, randomBytes(12));
      var aesKey = new SecretKeySpec(key, "AES");
      aes.init(Cipher.ENCRYPT_MODE, aesKey, gcmParameterSpec);

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

  public static byte[] decryptAes256Gcm(byte[] input, byte[] key) {
    try {
      Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");

      byte[] iv = EncodingUtils.subArray(input, 0, 12);
      byte[] cipherText = EncodingUtils.subArray(input, 12, input.length);

      var gcmParameterSpec = new GCMParameterSpec(128, iv);
      var aesKey = new SecretKeySpec(key, "AES");
      aes.init(Cipher.DECRYPT_MODE, aesKey, gcmParameterSpec);

      return aes.doFinal(cipherText);
    } catch (NoSuchAlgorithmException
        | NoSuchPaddingException
        | InvalidKeyException
        | InvalidAlgorithmParameterException
        | IllegalBlockSizeException
        | BadPaddingException e) {
      throw new RuntimeException(e);
    }
  }
}
