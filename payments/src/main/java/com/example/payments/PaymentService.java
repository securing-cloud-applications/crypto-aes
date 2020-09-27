package com.example.payments;

import com.example.util.CryptoUtils;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.stereotype.Component;

@Component
public class PaymentService {

  public void processRefunds(Path refundsFile, String key) {

    try {
      byte[] clearText =
          CryptoUtils.decryptAes256Gcm(Files.readAllBytes(refundsFile), key.getBytes());
      String refundsJson = new String(clearText);
      System.out.println("Issuing Refund to");
      System.out.println(refundsJson);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }
}
