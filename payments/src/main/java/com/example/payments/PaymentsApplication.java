package com.example.payments;

import java.nio.file.Path;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class PaymentsApplication implements CommandLineRunner {

  @Autowired private PaymentService paymentService;

  @Value("${refundsPath:data/refunds.aes}")
  private String refundsPath;

  @Value("${refunds.password}")
  private String password;

  @Value("${refunds.salt")
  private String salt;

  @Override
  public void run(String... args) {
    paymentService.processRefunds(Path.of(refundsPath), password, salt);
  }

  public static void main(String[] args) {
    SpringApplication.run(PaymentsApplication.class, args);
  }
}
