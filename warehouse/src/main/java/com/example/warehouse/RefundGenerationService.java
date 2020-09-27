package com.example.warehouse;

import com.example.util.CryptoUtils;
import com.example.util.JsonUtils;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.springframework.stereotype.Component;

@Component
public class RefundGenerationService {

  public void generateReport(Path refundsFile, List<Refund> refunds, String key) {
    try {
      String refundsJson = JsonUtils.toJson(refunds);
      byte[] cipherText = CryptoUtils.encryptAes256Gcm(refundsJson.getBytes(), key.getBytes());
      Files.write(refundsFile, cipherText);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }
}
