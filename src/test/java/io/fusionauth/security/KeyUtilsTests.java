/*
 * Copyright (c) 2020-2025, FusionAuth, All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

package io.fusionauth.security;

import io.fusionauth.pem.domain.PEM;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Base64;

import static org.testng.Assert.assertEquals;

/**
 * Note that the higher invocationCount parameters are helpful to indentify incorrect assumptions in key parsing.
 * <p>
 * Key lengths can differ, and when encoding larger integers in DER encode sequences, or parsing them in and out of
 * JWK formats, we want to be certain we are not making incorrect assumptions. During development, you may wish to
 * run some of these with 5-10k invocation counts to ensure these types of anomalies are un-covered and addressed.
 * <p>
 * It may be reasonable to reduce the invocation counts if tests take too long to run - once we know that the tests
 * will pass with a high number of invocations. However, the time is not yet that significant, and there is value to
 * ensuring that the same result can be expected regardless of the number of times we run the same test.
 *
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
  // failures where the key is not an exact size, and we have to figure out which key size it should be reported as.
  // - For testing locally, you can ramp up this invocation count to 100k or something like that to prove that we have
  //   consistency over time.
  @Test(dataProvider = "ecKeyLengths", invocationCount = 500)
  public void ec_getKeyLength(String algorithm, int keySize, int privateKeySize, int publicKeySize) throws Exception {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
    keyPairGenerator.initialize(keySize);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();

    assertEquals(KeyUtils.getKeyLength(keyPair.getPrivate()), privateKeySize);
    assertEquals(KeyUtils.getKeyLength(keyPair.getPublic()), publicKeySize);
  }

  // Failing tests
  @Test
  public void ec_getKeyLength_edgeCases() {
    // Expect 256
    assertEquals(length(Base64.getDecoder().decode("DNB60oX+xWMTHlJ7SIb+iF82+Z63d+8eCIT/fMlD")), 256);
    assertEquals(length(Base64.getDecoder().decode("TWe6inYp+73PCZoTuqhsorCUhnI2aAlbJ0OSMCqF")), 256);
    assertEquals(length(Base64.getDecoder().decode("TYiB2RgMiKmZWSIhigZUhkH8jhpZfH0/6iyMH2V2")), 256);
    assertEquals(length(Base64.getDecoder().decode("UGg/Zd/jzBEs+B0eMcye0Pe9sKijJKwIBfXCQ3F")), 256);

    // Expect 384
    assertEquals(length(Base64.getDecoder().decode("a/GTpNnarc1oMRnsjo9UTCrQpK1hNGNvbSbu+t3TJXksngWwt0URBgBYZCBn6A==")), 384);
    assertEquals(length(Base64.getDecoder().decode("F7jFw1gM0lg+PIKMpexZe97PfUHJ+BI0CBksNVOYNp9udXMf6HmkFuPTqm3l1Q==")), 384);
    assertEquals(length(Base64.getDecoder().decode("bqVtyl7NwwmUkAk0GCHeQCFhiF4m7rzfYrkIp5BDPECwOMkJjgbAbBrJkqZwXA==")), 384);
  }

  // Copy of the logic from getKeyLength for testing
  private int length(byte[] bytes) {
    int length = bytes.length;
    int mod = length % 8;
    if (mod >= 2) {
      length = length + (8 - mod);
    }

    return ((length / 8) * 8) * 8;
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

  @Test
  public void eddsa_25519_keyLength() throws Exception {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519");
    KeyPair keyPair = keyPairGenerator.generateKeyPair();

    assertEquals(KeyUtils.getKeyLength(keyPair.getPrivate()), 32);
    assertEquals(KeyUtils.getKeyLength(keyPair.getPublic()), 32);
  }

  @Test
  public void eddsa_448_keyLength() throws Exception {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed448");
    KeyPair keyPair = keyPairGenerator.generateKeyPair();

    assertEquals(KeyUtils.getKeyLength(keyPair.getPrivate()), 57);
    assertEquals(KeyUtils.getKeyLength(keyPair.getPublic()), 57);
  }
}
