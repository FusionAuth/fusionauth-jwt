/*
 * Copyright (c) 2020, FusionAuth, All Rights Reserved
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

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

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

  @Test
  public void generateX509Certificate() {
    String id = new UUID(1, 1).toString();
    String algorithm = "RS256";
    ZonedDateTime insertInstant = ZonedDateTime.of(2019, 4, 16, 12, 35, 0, 0, ZoneOffset.UTC);
    String publicKey = "  -----BEGIN PUBLIC KEY-----\n" +
                       "  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiZEea8bycpfgdLMtoeBy\n" +
                       "  /srPRayqLeSZmlEWMYQivPHrSyLDxxV+HzTpqX94dzBmpllYc28DFQc0lbsTYMz7\n" +
                       "  0HYeuWjsSqCsHsHzKKRZML0bV31AyPZnLCW9bn9rEWNpr0MlvJtfimGJtebBDGuK\n" +
                       "  wcgik1S0beE9dv+0m19qD/x4zPnNM8efaaPEO+qXhT2un5jITbfpNSTq6oOv8Vo9\n" +
                       "  DBME/HpmFbEe7uWp5IN1A4VqI0xVW7+Mo4bwoLQUlrOfu0EkRvLRNV/DborRO2uP\n" +
                       "  CDuPv3AlIffmW2FqvB+O/qi/crGVc7Msn/Y/myng5xb+ElU6Aep1QWhumH9Dkj1s\n" +
                       "  tQIDAQAB\n" +
                       "  -----END PUBLIC KEY-----\n";

    String privateKey = "  -----BEGIN PRIVATE KEY-----\n" +
                     "  MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCJkR5rxvJyl+B0\n" +
                     "  sy2h4HL+ys9FrKot5JmaURYxhCK88etLIsPHFX4fNOmpf3h3MGamWVhzbwMVBzSV\n" +
                     "  uxNgzPvQdh65aOxKoKwewfMopFkwvRtXfUDI9mcsJb1uf2sRY2mvQyW8m1+KYYm1\n" +
                     "  5sEMa4rByCKTVLRt4T12/7SbX2oP/HjM+c0zx59po8Q76peFPa6fmMhNt+k1JOrq\n" +
                     "  g6/xWj0MEwT8emYVsR7u5ankg3UDhWojTFVbv4yjhvCgtBSWs5+7QSRG8tE1X8Nu\n" +
                     "  itE7a48IO4+/cCUh9+ZbYWq8H47+qL9ysZVzsyyf9j+bKeDnFv4SVToB6nVBaG6Y\n" +
                     "  f0OSPWy1AgMBAAECggEAPRDyVB2IWl4ZATTYuNcNtRUKVX+EO8MSfHIqS+jAEufA\n" +
                     "  7yWLisB7sBao8tjm/OG7b3SR0wwgbiE4so7M11enIK6OjPeKjMYuIaku64epH/2S\n" +
                     "  OZAcRhk7S1mlcXuWZ62dqHNCOSsvihoqK1k3sO+8NLFGx+f+ABjQVBbGcYI1bsqZ\n" +
                     "  pUvutbtLO2QHE2BXnZYPSmqXGEaznnpKYTUXe60DIw0eZCH3DF0gmv99VddlK6fu\n" +
                     "  yn1lMzllhcOYaLZOBLzE3Zt6XCrVz6SsbDLepQgezJi1d33THD4CRzglw5Z1kPpO\n" +
                     "  znHB31i8DiLfVtq62f4VsfsCbdO531S+CjDVEho4sQKBgQC+NB81UDPej1iy2dvX\n" +
                     "  JiMhSOB5pNzDndAq9mV4TJJZGeKl6V7Z1tuCL3BjbWz2mAee/g181CP4StAT+SoX\n" +
                     "  ds+/BAPYiI+DED+ZhB3HpdpqC70+CeuIYOdiBa/7h0IrZHCk4WSN/9frMxS+a9Mo\n" +
                     "  KFndEbng/d+f8CKCbZy1/4MIRwKBgQC5J6QbD0+9skdisn3h7x85zt8nPz6DfaeH\n" +
                     "  kdkUwUmSovRYTjP7oPeABk/tMIsUnvozB9pbN4sHjygluWVksAEUHsF3mricBJSH\n" +
                     "  rWXL88T+XfaBJ7Vx+DYEPGYrxKZB/h02wU6TN4DD2KsuGdBsdpLAoLgr/UPkmhyE\n" +
                     "  Tjv/1mLdIwKBgASUaLP17GnNdctIp5x0lJ/2i0EikRY8tIh0SlktLtDqaKSqC9ie\n" +
                     "  7cYiskgSmG8Plg9j+pso2HzgAEaa10KdX78vr5AFKb90IrPllHn8KlgnVDUsM/mi\n" +
                     "  q6+Wh3g894Dn+DZgHvW0VVSadENpgToUTqWeCaW7Nyk4tPwC+6T+M/99AoGAEF/1\n" +
                     "  H3+HKduufIgUofqn5FDrY2kweiiOvGqlrDQ78X//5B9mcYaW3Pex8eQtKLG2pvS2\n" +
                     "  1wJehVif0FZJJVJ7hfACZDWGxiWRjT5ElnkEnwpoVpvQbDfrbwx4bL6DhaqXotQN\n" +
                     "  wu9RsABlgzo9OJpz+B0+rIVFj94hT4IrxECNlckCgYEAtuN0UO1XMBbOrO8xQvyG\n" +
                     "  eO5hDI5zAh7navaLfkdJoM4kBvUDastdx1Bd7wpXrlcNqZK5Ehu215yDFvZvNNsq\n" +
                     "  KjBMltIJUFAISVS4O7t4D8ndEV61QWQMbi2VSM1cVqx4hDtn8w51WMOGr/x3XQGQ\n" +
                     "  AZaJrIZOwRV6pTjplAncmZs=\n" +
                     "  -----END PRIVATE KEY-----\n";

    String issuer = "fusionauth.io";

    PublicKey publicKeyO = PEM.decode(publicKey).publicKey;
    PrivateKey privateKeyO = PEM.decode(privateKey).privateKey;
    X509Certificate cert = KeyUtils.generateX509CertificateFromKey(id, algorithm, insertInstant, issuer, publicKeyO, privateKeyO);
    String encodedCert = PEM.encode(cert);
    System.out.println(encodedCert);

    assertEquals(cert.getIssuerDN().getName(), "CN=fusionauth.io");
    assertEquals(cert.getNotBefore(), Date.from(insertInstant.toInstant()));
    assertEquals(cert.getNotAfter(), Date.from(insertInstant.plusYears(10).toInstant()));
    assertEquals(cert.getPublicKey().getEncoded(), PEM.decode(publicKey).publicKey.getEncoded());
    assertEquals(cert.getSerialNumber(), BigInteger.valueOf(1).shiftLeft(64).add(BigInteger.valueOf(1)));
    assertEquals(cert.getSubjectDN().getName(), "CN=fusionauth.io");
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
}
