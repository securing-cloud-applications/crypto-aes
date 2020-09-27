# crypto-aes

Demo project showing how to use AES in GCM mode with 256-bit key to guarantee integrity,
 authenticity, and confidentiality between two applications. There are three subprojects in this repo.

* utils - contains shared utility classes `CrptoUtils` and `JsonUtils`.  
* warehouse - generates `data/refunds.aes` file encrypted with AES/GCM, depends on the utils project. 
* payments -  reads and decrypts `data/refunds.aes`, depends on utils project.

## software prerequisites 

* Java 11 JDK 
* Java IDE 

## run on the command line

* run warehouse app `java -jar warehouse/target/warehouse-0.0.1-SNAPSHOT.jar` to generate the 
  `data/refunds.aen` file
* run payments app `java -jar payments/target/payments-0.0.1-SNAPSHOT.jar` to read the 
  `data/refunds.aes` and verify and decrypt it.
* edit `data/refunds.aes` to simulate corruption. you can add a newline at the end of the file.
* run payments app `java -jar payments/target/payments-0.0.1-SNAPSHOT.jar` you will an exception. 

## run from the IDE 

* run `com.example.warehouse.WarehouseApplication` to generate the `data/refunds.aes`
* run `com.example.payments.PaymentsApplication` to read the `data/refunds.aes`  verify and decrypt 
* edit `data/refunds.aes` to simulate corruption. you can add a newline at the end of the file.
* run `com.example.payments.PaymentsApplication` to get a data corruption exception 
* restore `data/refunds.aes` to its original state
* edit the refunds password in `payments/src/main/resources/application.yml`
* run `com.example.payments.PaymentsApplication` to get a data corruption exception 

## interesting files to look at 

* `util/src/main/java/com/example/util/CryptoUtils.java` to examine AES encryption
* `warehouse/src/main/java/com/example/warehouse/RefundGenerationService.java` to examine the code
that generates the `refund.aes` file
* `payments/src/main/java/com/example/payments/PaymentService.java` to examine the code that 
 verifies and decrypts the `refund.aes` file before consuming it.
