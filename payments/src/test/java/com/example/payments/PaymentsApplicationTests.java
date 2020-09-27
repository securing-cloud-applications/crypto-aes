package com.example.payments;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(args = "--refundsPath=../data/refunds.aes")
class PaymentsApplicationTests {

  @Test
  void contextLoads() {}
}
