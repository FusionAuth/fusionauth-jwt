package io.fusionauth.security;

import io.fusionauth.pem.domain.PEM;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;

import static org.testng.Assert.assertEquals;

/**
 * @author Daniel DeGroff
 */
public class KeyUtilsTests {
  @DataProvider(name = "ecKeyLengths")
  public Object[][] ecKeyLengths() {
    return new Object[][]{
        {"EC", 256, 256, 256},
        {"EC", 384, 384, 384},
        {"EC", 521, 521, 521}
    };
  }

  @DataProvider(name = "rsaKeyLengths")
  public Object[][] rsaKeyLengths() {
    return new Object[][]{
        {"RSA", 2048, 2048, 2048},
        {"RSA", 3072, 3072, 3072},
        {"RSA", 4096, 4096, 4096}
    };
  }

  @Test
  public void problematicKey() {
    // Fixing a problematic EC key length which is not a multiple of 8 bytes.
    PublicKey key = PEM.decode(
        "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEABGGbHRp5Rv+sm86OfuPqnkYCmUzuUDW\nfJPXIgZUeqo7JY5mTALqdMYYi93rh0xpkLzFrwZGSYv8gGwR9t5d3901L0CZuX6X\nHob0RbKzwdAEdykcBPxpar7k8jVGCo8m\n-----END PUBLIC KEY-----")
        .publicKey;
    assertEquals(KeyUtils.getKeyLength(key), 384);
  }

  // Running 500 times to ensure we get consistency. EC keys can vary in length, but the "reported" size returned
  // from the .getKeyLength() should be consistent. Out of 500 tests (if we had an error in the logic) we may get 1-5
  // failures where the key is not an exact size and we have to figure out which key size it should be reported as.
  @Test(dataProvider = "ecKeyLengths", invocationCount = 500)
  public void ec_getKeyLength(String algorithm, int keySize, int privateKeySize, int publicKeySize) throws Exception {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
    keyPairGenerator.initialize(keySize);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();

    assertEquals(KeyUtils.getKeyLength(keyPair.getPrivate()), privateKeySize);
    assertEquals(KeyUtils.getKeyLength(keyPair.getPublic()), publicKeySize);
  }

  // Only run this test once, the RSA key lengths are predictable based upon the size of the modulus.
  @Test(dataProvider = "rsaKeyLengths")
  public void rsa_getKeyLength(String algorithm, int keySize, int privateKeySize, int publicKeySize) throws Exception {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
    keyPairGenerator.initialize(keySize);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();

    assertEquals(KeyUtils.getKeyLength(keyPair.getPrivate()), privateKeySize);
    assertEquals(KeyUtils.getKeyLength(keyPair.getPublic()), publicKeySize);
  }
}
