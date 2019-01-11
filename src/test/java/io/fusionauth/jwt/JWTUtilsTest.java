/*
 * Copyright (c) 2016-2019, FusionAuth, All Rights Reserved
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

package io.fusionauth.jwt;

import io.fusionauth.jwt.domain.KeyPair;
import io.fusionauth.pem.domain.PEM;
import org.testng.annotations.Test;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import static io.fusionauth.pem.domain.PEM.PKCS_8_PRIVATE_KEY_PREFIX;
import static io.fusionauth.pem.domain.PEM.PKCS_8_PRIVATE_KEY_SUFFIX;
import static io.fusionauth.pem.domain.PEM.X509_PUBLIC_KEY_PREFIX;
import static io.fusionauth.pem.domain.PEM.X509_PUBLIC_KEY_SUFFIX;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * @author Daniel DeGroff
 */
public class JWTUtilsTest {
  @Test
  public void generateECKey() {
    // 256 bit key
    KeyPair keyPair256 = JWTUtils.generate256_ECKeyPair();
    ECPrivateKey privateKey256 = PEM.decode(keyPair256.privateKey).getPrivateKey();
    ECPublicKey publicKey256 = PEM.decode(keyPair256.publicKey).getPublicKey();

    assertEquals(privateKey256.getAlgorithm(), "EC");
    assertEquals(privateKey256.getFormat(), "PKCS#8");
    assertEquals(privateKey256.getParams().getCurve().getField().getFieldSize(), 256);

    assertEquals(publicKey256.getAlgorithm(), "EC");
    assertEquals(publicKey256.getFormat(), "X.509");
    assertEquals(publicKey256.getParams().getCurve().getField().getFieldSize(), 256);

    assertPrefix(keyPair256.privateKey, PKCS_8_PRIVATE_KEY_PREFIX);
    assertSuffix(keyPair256.privateKey, PKCS_8_PRIVATE_KEY_SUFFIX);
    assertPrefix(keyPair256.publicKey, X509_PUBLIC_KEY_PREFIX);
    assertSuffix(keyPair256.publicKey, X509_PUBLIC_KEY_SUFFIX);

    // Now go backwards from the key to a PEM and assert they come out the same.
    String actualPrivateKey256 = PEM.encode(privateKey256);
    String actualPublicKey256 = PEM.encode(publicKey256);
    assertEquals(actualPrivateKey256, keyPair256.privateKey);
    assertEquals(actualPublicKey256, keyPair256.publicKey);

    // 384 bit key
    KeyPair keyPair384 = JWTUtils.generate384_ECKeyPair();
    ECPrivateKey privateKey384 = PEM.decode(keyPair384.privateKey).getPrivateKey();
    ECPublicKey publicKey384 = PEM.decode(keyPair384.publicKey).getPublicKey();

    assertEquals(privateKey384.getAlgorithm(), "EC");
    assertEquals(privateKey384.getFormat(), "PKCS#8");
    assertEquals(privateKey384.getParams().getCurve().getField().getFieldSize(), 384);

    assertEquals(publicKey384.getAlgorithm(), "EC");
    assertEquals(publicKey384.getFormat(), "X.509");
    assertEquals(publicKey384.getParams().getCurve().getField().getFieldSize(), 384);

    assertPrefix(keyPair384.privateKey, PKCS_8_PRIVATE_KEY_PREFIX);
    assertSuffix(keyPair384.privateKey, PKCS_8_PRIVATE_KEY_SUFFIX);
    assertPrefix(keyPair384.publicKey, X509_PUBLIC_KEY_PREFIX);
    assertSuffix(keyPair384.publicKey, X509_PUBLIC_KEY_SUFFIX);

    // Now go backwards from the key to a PEM and assert they come out the same.
    String actualPrivateKey384 = PEM.encode(privateKey384);
    String actualPublicKey384 = PEM.encode(publicKey384);
    assertEquals(actualPrivateKey384, keyPair384.privateKey);
    assertEquals(actualPublicKey384, keyPair384.publicKey);

    // 521 bit key
    KeyPair keyPair521 = JWTUtils.generate521_ECKeyPair();
    ECPrivateKey privateKey521 = PEM.decode(keyPair521.privateKey).getPrivateKey();
    ECPublicKey publicKey521 = PEM.decode(keyPair521.publicKey).getPublicKey();

    assertEquals(privateKey521.getAlgorithm(), "EC");
    assertEquals(privateKey521.getFormat(), "PKCS#8");
    assertEquals(privateKey521.getParams().getCurve().getField().getFieldSize(), 521);

    assertEquals(publicKey521.getAlgorithm(), "EC");
    assertEquals(publicKey521.getFormat(), "X.509");
    assertEquals(publicKey521.getParams().getCurve().getField().getFieldSize(), 521);

    assertPrefix(keyPair521.privateKey, PKCS_8_PRIVATE_KEY_PREFIX);
    assertSuffix(keyPair521.privateKey, PKCS_8_PRIVATE_KEY_SUFFIX);
    assertPrefix(keyPair521.publicKey, X509_PUBLIC_KEY_PREFIX);
    assertSuffix(keyPair521.publicKey, X509_PUBLIC_KEY_SUFFIX);

    // Now go backwards from the key to a PEM and assert they come out the same.
    String actualPrivateKey521 = PEM.encode(privateKey521);
    String actualPublicKey521 = PEM.encode(publicKey521);
    assertEquals(actualPrivateKey521, keyPair521.privateKey);
    assertEquals(actualPublicKey521, keyPair521.publicKey);
  }

  @Test
  public void generateRSAKey() {
    // 2048 bit key
    KeyPair keyPair2048 = JWTUtils.generate2048_RSAKeyPair();
    RSAPrivateKey privateKey2048 = PEM.decode(keyPair2048.privateKey).getPrivateKey();
    RSAPublicKey publicKey2048 = PEM.decode(keyPair2048.publicKey).getPublicKey();

    assertEquals(privateKey2048.getModulus().bitLength(), 2048);
    assertEquals(privateKey2048.getAlgorithm(), "RSA");
    assertEquals(privateKey2048.getFormat(), "PKCS#8");

    assertEquals(publicKey2048.getModulus().bitLength(), 2048);
    assertEquals(publicKey2048.getAlgorithm(), "RSA");
    assertEquals(publicKey2048.getFormat(), "X.509");

    assertPrefix(keyPair2048.privateKey, PKCS_8_PRIVATE_KEY_PREFIX);
    assertSuffix(keyPair2048.privateKey, PKCS_8_PRIVATE_KEY_SUFFIX);
    assertPrefix(keyPair2048.publicKey, X509_PUBLIC_KEY_PREFIX);
    assertSuffix(keyPair2048.publicKey, X509_PUBLIC_KEY_SUFFIX);

    // Now go backwards from the key to a PEM and assert they come out the same.
    String actualPrivateKey2048 = PEM.encode(privateKey2048);
    String actualPublicKey2048 = PEM.encode(publicKey2048);
    assertEquals(actualPrivateKey2048, keyPair2048.privateKey);
    assertEquals(actualPublicKey2048, keyPair2048.publicKey);

    // 3072 bit key
    KeyPair keyPair3072 = JWTUtils.generate3072_RSAKeyPair();
    RSAPrivateKey privateKey3072 = PEM.decode(keyPair3072.privateKey).getPrivateKey();
    RSAPublicKey publicKey3072 = PEM.decode(keyPair3072.publicKey).getPublicKey();

    assertEquals(privateKey3072.getModulus().bitLength(), 3072);
    assertEquals(privateKey3072.getAlgorithm(), "RSA");
    assertEquals(privateKey3072.getFormat(), "PKCS#8");

    assertEquals(publicKey3072.getModulus().bitLength(), 3072);
    assertEquals(publicKey3072.getAlgorithm(), "RSA");
    assertEquals(publicKey3072.getFormat(), "X.509");

    assertPrefix(keyPair3072.privateKey, PKCS_8_PRIVATE_KEY_PREFIX);
    assertSuffix(keyPair3072.privateKey, PKCS_8_PRIVATE_KEY_SUFFIX);
    assertPrefix(keyPair3072.publicKey, X509_PUBLIC_KEY_PREFIX);
    assertSuffix(keyPair3072.publicKey, X509_PUBLIC_KEY_SUFFIX);

    // Now go backwards from the key to a PEM and assert they come out the same.
    String actualPrivateKey3072 = PEM.encode(privateKey3072);
    String actualPublicKey3072 = PEM.encode(publicKey3072);
    assertEquals(actualPrivateKey3072, keyPair3072.privateKey);
    assertEquals(actualPublicKey3072, keyPair3072.publicKey);

    // 4096 bit key
    KeyPair keyPair4096 = JWTUtils.generate4096_RSAKeyPair();
    RSAPrivateKey privateKey4096 = PEM.decode(keyPair4096.privateKey).getPrivateKey();
    RSAPublicKey publicKey4096 = PEM.decode(keyPair4096.publicKey).getPublicKey();

    assertEquals(privateKey4096.getModulus().bitLength(), 4096);
    assertEquals(privateKey4096.getAlgorithm(), "RSA");
    assertEquals(privateKey4096.getFormat(), "PKCS#8");

    assertEquals(publicKey4096.getModulus().bitLength(), 4096);
    assertEquals(publicKey4096.getAlgorithm(), "RSA");
    assertEquals(publicKey4096.getFormat(), "X.509");

    assertPrefix(keyPair4096.privateKey, PKCS_8_PRIVATE_KEY_PREFIX);
    assertSuffix(keyPair4096.privateKey, PKCS_8_PRIVATE_KEY_SUFFIX);
    assertPrefix(keyPair4096.publicKey, X509_PUBLIC_KEY_PREFIX);
    assertSuffix(keyPair4096.publicKey, X509_PUBLIC_KEY_SUFFIX);

    // Now go backwards from the key to a PEM and assert they come out the same.
    String actualPrivateKey4096 = PEM.encode(privateKey4096);
    String actualPublicKey4096 = PEM.encode(publicKey4096);
    assertEquals(actualPrivateKey4096, keyPair4096.privateKey);
    assertEquals(actualPublicKey4096, keyPair4096.publicKey);
  }

  @Test
  public void hmacSecretLengths() {
    String hmac256 = JWTUtils.generateSHA256_HMACSecret();
    assertEquals(hmac256.length(), 44);
    assertEquals(Base64.getDecoder().decode(hmac256.getBytes(StandardCharsets.UTF_8)).length, 32);

    String hmac384 = JWTUtils.generateSHA384_HMACSecret();
    assertEquals(hmac384.length(), 64);
    assertEquals(Base64.getDecoder().decode(hmac384.getBytes(StandardCharsets.UTF_8)).length, 48);

    String hmac512 = JWTUtils.generateSHA512_HMACSecret();
    assertEquals(hmac512.length(), 88);
    assertEquals(Base64.getDecoder().decode(hmac512.getBytes(StandardCharsets.UTF_8)).length, 64);
  }

  @Test
  public void jws_x5t() {
    String encodedCertificate = "MIIC5jCCAc6gAwIBAgIQNCdDZLmeeL5H6O2BE+aQCjANBgkqhkiG9w0BAQsFADAvMS0wKwYDVQQDEyRBREZTIFNpZ25pbmcgLSB1bWdjb25uZWN0LnVtdXNpYy5jb20wHhcNMTcxMDE4MTUyOTAzWhcNMTgxMDE4MTUyOTAzWjAvMS0wKwYDVQQDEyRBREZTIFNpZ25pbmcgLSB1bWdjb25uZWN0LnVtdXNpYy5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDnUl7AwWO1fjpijswRY40bs8jegA4Kz4ycM12h8PqD0CbydWyCnPmY/mzI8EPWsaT3uJ4QaYEEq+taNTu/GB8eFDs1flDb1JNjkZ2ECDZpdwgAS/z+RvI7D+tRARNUU7QvkMAOfFTb3zS4Cx52RoXlp3Bdrtzk9KaO/DJc7IoxLCAWuXL8kxuBRwfPzeQXX/i+wIRtkJAFotOq7j/XxgYO0/UzCenZDAr+Xbl8JfmrkFaegEQFwAC2/jlAP9OYjF39qD+9kI/HP9CcnXxoAIbq8lJkIKvuoURV9mErlel2Oj+tgvveq28NEV36RwqnfAqAIsAT4BTs739JUsnoHnKbAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAGesHLA8V2/4ljxwbjeBsBBk8fJ4DGVufKJJXBit7jb37/9/XVtkVg1Y2IuVoYnzpnOxAZ/Zizp8/HKH2bApqEOcAU3oZ471FZlzXAv1G51S0i1UUD/OWgc3z84pk9AMtWSka26GOWA4pb/Mw/nrBrG3R8NY6ZgLZQqbYR2GQBj5JXbDsJtzYkVXY6N5KmsBekVJ92ddjKMy5SfcGY0j3BFFsBOUpaONWgBFAD2rOH9FnwoY7tcTKa5u4MfwSXMYLal/Vk9kFAtBV2Uqe/MgitB8OgAGYYqGU8VRPVH4K/n8sx5EarZPXcOJkHbI/C70Puc0jxra4e4/2c4HqifMAYQ=";
    byte[] derEncodedCertificate = Base64.getDecoder().decode(encodedCertificate.getBytes(Charset.forName("UTF-8")));

    // Pass in Base64 encode certificate
    assertEquals(JWTUtils.generateJWS_x5t(encodedCertificate), "vDT213a_AF5eRdElKZla9-9dpc8");
    assertEquals(JWTUtils.generateJWS_x5t("SHA-1", encodedCertificate), "vDT213a_AF5eRdElKZla9-9dpc8");

    // Pass in DER encoded certificate
    assertEquals(JWTUtils.generateJWS_x5t(derEncodedCertificate), "vDT213a_AF5eRdElKZla9-9dpc8");
    assertEquals(JWTUtils.generateJWS_x5t("SHA-1", derEncodedCertificate), "vDT213a_AF5eRdElKZla9-9dpc8");

    // Base64 Encoded and DER Encoded using SHA-256
    assertEquals(JWTUtils.generateJWS_x5t("SHA-256", encodedCertificate), "tIFNLfPYY14sM0DLTp6T-BZ3yPaPUPKc8Hnh6evXTeM");
    assertEquals(JWTUtils.generateJWS_x5t("SHA-256", derEncodedCertificate), "tIFNLfPYY14sM0DLTp6T-BZ3yPaPUPKc8Hnh6evXTeM");

    // Convert HEX SHA-1 Fingerprint --> x5t
    assertEquals(JWTUtils.convertFingerprintToThumbprint("BC34F6D776BF005E5E45D12529995AF7EF5DA5CF"), "vDT213a_AF5eRdElKZla9-9dpc8");
    // Convert SHA-256 Fingerprint to x5t#256
    assertEquals(JWTUtils.convertFingerprintToThumbprint("B4814D2DF3D8635E2C3340CB4E9E93F81677C8F68F50F29CF079E1E9EBD74DE3"), "tIFNLfPYY14sM0DLTp6T-BZ3yPaPUPKc8Hnh6evXTeM");

    // Convert x5t --> HEX SHA-1 Fingerprint
    assertEquals(JWTUtils.convertThumbprintToFingerprint("vDT213a_AF5eRdElKZla9-9dpc8"), "BC34F6D776BF005E5E45D12529995AF7EF5DA5CF");
    // Convert x5t#256 --> HEX SHA-256 Fingerprint
    assertEquals(JWTUtils.convertThumbprintToFingerprint("tIFNLfPYY14sM0DLTp6T-BZ3yPaPUPKc8Hnh6evXTeM"), "B4814D2DF3D8635E2C3340CB4E9E93F81677C8F68F50F29CF079E1E9EBD74DE3");
  }

  private void assertPrefix(String key, String prefix) {
    assertTrue(key.startsWith(prefix));
  }

  private void assertSuffix(String key, String suffix) {
    String trimmed = key.trim();
    assertTrue(trimmed.endsWith(suffix));
  }
}
