/*
 * Copyright (c) 2016-2022, FusionAuth, All Rights Reserved
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

import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import io.fusionauth.jwt.domain.Header;
import io.fusionauth.jwt.domain.JWT;
import io.fusionauth.jwt.ec.EC;
import io.fusionauth.jwt.ec.ECSigner;
import io.fusionauth.jwt.ec.ECVerifier;
import io.fusionauth.jwt.hmac.HMAC;
import io.fusionauth.jwt.hmac.HMACSigner;
import io.fusionauth.jwt.hmac.HMACVerifier;
import io.fusionauth.jwt.rsa.RSAPSSSigner;
import io.fusionauth.jwt.rsa.RSAPSSVerifier;
import io.fusionauth.jwt.rsa.RSASigner;
import io.fusionauth.jwt.rsa.RSAVerifier;
import io.fusionauth.pem.domain.PEM;
import io.fusionauth.security.BCFIPSCryptoProvider;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.testng.annotations.Test;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/**
 * @author Daniel DeGroff
 */
public class JWTTest extends BaseJWTTest {
  @Test(enabled = false)
  public void buildSignerPerformance() throws Exception {
    long iterationCount = 500_000;
    String privateKey = new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_private_key_2048.pem")));

    Instant start = Instant.now();
    for (int i = 0; i < iterationCount; i++) {
      RSASigner.newSHA256Signer(privateKey);
    }

    Duration duration = Duration.between(start, Instant.now());
    BigDecimal durationInMillis = BigDecimal.valueOf(duration.toMillis());
    BigDecimal average = durationInMillis.divide(BigDecimal.valueOf(iterationCount), RoundingMode.HALF_DOWN);
    long perSecond = iterationCount / (duration.toMillis() / 1000);

    System.out.println("[Build Signer] " + duration.toMillis() + " milliseconds total. [" + iterationCount + "] iterations. [" + average + "] milliseconds per iteration. Approx. [" + perSecond + "] per second.");

    // 500,000 Iterations
    // - Reading file and building signer
    //   --> Results [Build Signer] 28274 milliseconds total. [500000] iterations. [0] milliseconds per iteration. Approx. [17,857] per second.
    ///
    // - Build Signer Only
    //   --> Results [Build Signer] 15443 milliseconds total. [500000] iterations. [0] milliseconds per iteration. Approx. [33,333] per second.
  }

  @Test(enabled = false)
  public void buildVerifierPerformance() throws Exception {
    long iterationCount = 500_000;
    String publicKey = new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_public_key_2048.pem")));

    Instant start = Instant.now();
    for (int i = 0; i < iterationCount; i++) {
      RSAVerifier.newVerifier(publicKey);
    }

    Duration duration = Duration.between(start, Instant.now());
    BigDecimal durationInMillis = BigDecimal.valueOf(duration.toMillis());
    BigDecimal average = durationInMillis.divide(BigDecimal.valueOf(iterationCount), RoundingMode.HALF_DOWN);
    long perSecond = iterationCount / (duration.toMillis() / 1000);

    System.out.println("[Build Verifier] " + duration.toMillis() + " milliseconds total. [" + iterationCount + "] iterations. [" + average + "] milliseconds per iteration. Approx. [" + perSecond + "] per second.");

    // 500,000 Iterations
    // - Reading file and building verifier
    //   --> Results [Build Verifier] 14778 milliseconds total. [500000] iterations. [0] milliseconds per iteration. Approx. [35,714] per second.
    ///
    // - Build Verifier Only
    //   --> Results [Build Verifier] 4969 milliseconds total. [500000] iterations. [0] milliseconds per iteration. Approx. [125,000] per second.
  }

  /**
   * Performance
   * <pre>
   *   Performance Summary:
   *   - HMAC is dramatically faster
   *   - SHA length does not dramatically affect the results
   *   - Size of JWT will negatively affect the performance of encoding and decoding
   *   - Verifying an RSA signature is much faster than generating the signature
   *
   *   Performance Recommendations:
   *   - Keep the JWT as small as possible
   *   - Use HMAC when you can safely share the HMAC secret or performance is paramount
   * </pre>
   */
  @Test(enabled = false)
  public void decoding_performance() throws Exception {
    String secret = JWTUtils.generateSHA256_HMACSecret();
    Signer hmacSigner = HMACSigner.newSHA256Signer(secret);
    Signer rsaSigner = RSASigner.newSHA256Signer(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_private_key_2048.pem"))));

    Verifier hmacVerifier = HMACVerifier.newVerifier(secret);
    Verifier rsaVerifier = RSAVerifier.newVerifier(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_public_key_2048.pem"))));

    JWT jwt = new JWT().setSubject(UUID.randomUUID().toString())
                       .addClaim("exp", ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(5).toInstant().toEpochMilli())
                       .setAudience(UUID.randomUUID().toString())
                       .addClaim("roles", new ArrayList<>(Arrays.asList("admin", "user")))
                       .addClaim("iat", ZonedDateTime.now(ZoneOffset.UTC).toInstant().toEpochMilli())
                       .setIssuer("inversoft.com");

    long iterationCount = 250_000;
    for (Verifier verifier : Arrays.asList(hmacVerifier, rsaVerifier)) {
      Instant start = Instant.now();
      Signer signer = verifier instanceof HMACVerifier ? hmacSigner : rsaSigner;
// Uncomment the following line to run without a signer, no signature, no verification is very fast.
//      Signer signer = new UnsecuredSigner();
      String encodedJWT = JWT.getEncoder().encode(jwt, signer);

      for (int i = 0; i < iterationCount; i++) {
        JWT.getDecoder().decode(encodedJWT, verifier);
// Uncomment the following line to run without a signer, no signature, no verification is very fast.
//        JWT.getDecoder().decode(encodedJWT); // no verifier, no signature
      }

      Duration duration = Duration.between(start, Instant.now());
      BigDecimal durationInMillis = BigDecimal.valueOf(duration.toMillis());
      BigDecimal average = durationInMillis.divide(BigDecimal.valueOf(iterationCount), RoundingMode.HALF_DOWN);
      long perSecond = iterationCount / (duration.toMillis() / 1000);

      System.out.println("[" + signer.getAlgorithm().value + "] " + duration.toMillis() + " milliseconds total. [" + iterationCount + "] iterations. [" + average + "] milliseconds per iteration. Approx. [" + perSecond + "] per second.");

    }
  }

  @Test(enabled = false)
  public void encoding_performance() throws Exception {
    Signer hmacSigner = HMACSigner.newSHA256Signer(JWTUtils.generateSHA256_HMACSecret());
    Signer rsaSigner = RSASigner.newSHA256Signer(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_private_key_2048.pem"))));

    JWT jwt = new JWT().setSubject(UUID.randomUUID().toString())
                       .addClaim("exp", ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(5).toInstant().toEpochMilli())
                       .setAudience(UUID.randomUUID().toString())
                       .addClaim("roles", new ArrayList<>(Arrays.asList("admin", "user")))
                       .addClaim("iat", ZonedDateTime.now(ZoneOffset.UTC).toInstant().toEpochMilli())
                       .setIssuer("inversoft.com");

    long iterationCount = 10_000;
    for (Signer signer : Arrays.asList(hmacSigner, rsaSigner)) {
// Uncomment the following line to run without a signer, no signature, no verification is very fast.
//      signer = new UnsecuredSigner();
      Instant start = Instant.now();
      for (int i = 0; i < iterationCount; i++) {
        JWT.getEncoder().encode(jwt, signer);
      }
      Duration duration = Duration.between(start, Instant.now());
      BigDecimal durationInMillis = BigDecimal.valueOf(duration.toMillis());
      BigDecimal average = durationInMillis.divide(BigDecimal.valueOf(iterationCount), RoundingMode.HALF_DOWN);
      long perSecond = iterationCount / (duration.toMillis() / 1000);

      System.out.println("[" + signer.getAlgorithm().value + "] " + duration.toMillis() + " milliseconds total. [" + iterationCount + "] iterations. [" + average + "] milliseconds per iteration. Approx. [" + perSecond + "] per second.");
    }
  }

  @Test
  public void expired() {
    // no expiration
    assertFalse(new JWT()
                    .setSubject("123456789").isExpired());

    assertFalse(new JWT()
                    .setExpiration(ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(1))
                    .setSubject("123456789").isExpired());

    assertTrue(new JWT()
                   .setExpiration(ZonedDateTime.now(ZoneOffset.UTC).minusMinutes(1))
                   .setSubject("123456789").isExpired());

    // Account for 59 seconds of skew, expired.
    assertTrue(new JWT()
                   .setExpiration(ZonedDateTime.now(ZoneOffset.UTC).minusMinutes(1))
                   .setSubject("123456789").isExpired(ZonedDateTime.now(ZoneOffset.UTC).minusSeconds(59)));

    // Account for 61 seconds of skew, not expired.
    assertFalse(new JWT()
                    .setExpiration(ZonedDateTime.now(ZoneOffset.UTC).minusMinutes(1))
                    .setSubject("123456789").isExpired(ZonedDateTime.now(ZoneOffset.UTC).minusSeconds(61)));
  }

  @Test
  public void test_EC_privateKey_needsConversionTo_pkcs_8() {
    JWT jwt = new JWT()
        .setSubject("1234567890")
        .addClaim("name", "John Doe")
        .addClaim("admin", true)
        .addClaim("iat", 1516239022);

    // EC Private key, needs to be encapulated to a PKCS#8 to be parsed by Java
    Signer signer = ECSigner.newSHA512Signer(
        "-----BEGIN EC PRIVATE KEY-----\n" +
        "MIHcAgEBBEIBiyAa7aRHFDCh2qga9sTUGINE5jHAFnmM8xWeT/uni5I4tNqhV5Xx\n" +
        "0pDrmCV9mbroFtfEa0XVfKuMAxxfZ6LM/yKgBwYFK4EEACOhgYkDgYYABAGBzgdn\n" +
        "P798FsLuWYTDDQA7c0r3BVk8NnRUSexpQUsRilPNv3SchO0lRw9Ru86x1khnVDx+\n" +
        "duq4BiDFcvlSAcyjLACJvjvoyTLJiA+TQFdmrearjMiZNE25pT2yWP1NUndJxPcv\n" +
        "VtfBW48kPOmvkY4WlqP5bAwCXwbsKrCgk6xbsp12ew==\n" +
        "-----END EC PRIVATE KEY-----");
    String encodedJWT = JWT.getEncoder().encode(jwt, signer, header
        -> header.set("kid", "xZDfZpry4P9vZPZyG2fNBRj-7Lz5omVdm7tHoCgSNfY"));

    Verifier verifier = ECVerifier.newVerifier(
        "-----BEGIN PUBLIC KEY-----\n" +
        "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBgc4HZz+/fBbC7lmEww0AO3NK9wVZ\n" +
        "PDZ0VEnsaUFLEYpTzb90nITtJUcPUbvOsdZIZ1Q8fnbquAYgxXL5UgHMoywAib47\n" +
        "6MkyyYgPk0BXZq3mq4zImTRNuaU9slj9TVJ3ScT3L1bXwVuPJDzpr5GOFpaj+WwM\n" +
        "Al8G7CqwoJOsW7Kddns=\n" +
        "-----END PUBLIC KEY-----");
    JWT actual = JWT.getDecoder().decode(encodedJWT, verifier);

    assertEquals(actual.subject, jwt.subject);
  }

  @Test
  public void test_ES() throws IOException {
    Signer signer = ECSigner.newSHA256Signer(new String(Files.readAllBytes(Paths.get("src/test/resources/ec_private_key_control.pem"))));
    Verifier verifier = ECVerifier.newVerifier(new String(Files.readAllBytes(Paths.get("src/test/resources/ec_public_key_p_256_control.pem"))));

    JWT jwt = new JWT().setSubject("123456789");
    String encodedJWT = JWT.getEncoder().encode(jwt, signer);
    JWT decoded = JWT.getDecoder().decode(encodedJWT, verifier);
    assertNotNull(decoded);
    assertEquals(decoded.subject, "123456789");
  }

  @Test
  public void test_ES256() {
    String encodedJWT = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.vPn7xrCNOLWbBRaWdVn53ddj2hW0E87FYl4gPnWy5d1Qj3WgyF8FS6I_hj_3kIJ77tbvy0GXdr7fO91NeWMD1A";
    Verifier verifier = ECVerifier.newVerifier(Paths.get("src/test/resources/ec_public_key_p_256.pem"));
    JWT jwt = JWT.getDecoder().decode(encodedJWT, verifier);
    assertEquals(jwt.subject, "123456789");
    assertEquals(jwt.header.algorithm, EC.ES256);
    assertEquals(jwt.header.type, "JWT");

    // Re-test using a pre-built EC Public Key
    assertEquals(JWT.getDecoder().decode(encodedJWT, ECVerifier.newVerifier((ECPublicKey) PEM.decode(Paths.get("src/test/resources/ec_public_key_p_256.pem")).getPublicKey())).subject, "123456789");
  }

  @Test
  public void test_ES256_BC_FIPS() {
    Security.addProvider(new BouncyCastleFipsProvider());
    String encodedJWT = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.vPn7xrCNOLWbBRaWdVn53ddj2hW0E87FYl4gPnWy5d1Qj3WgyF8FS6I_hj_3kIJ77tbvy0GXdr7fO91NeWMD1A";
    Verifier verifier = ECVerifier.newVerifier(Paths.get("src/test/resources/ec_public_key_p_256.pem"), new BCFIPSCryptoProvider());
    JWT jwt = JWT.getDecoder().decode(encodedJWT, verifier);
    assertEquals(jwt.subject, "123456789");

    // Re-test using a pre-built EC Public Key
    assertEquals(JWT.getDecoder().decode(encodedJWT, ECVerifier.newVerifier((ECPublicKey) PEM.decode(Paths.get("src/test/resources/ec_public_key_p_256.pem")).getPublicKey())).subject, "123456789");
  }

  @Test(expectedExceptions = RuntimeException.class)
  public void test_ES256_BC_FIPS_notAvailable() {
    // RuntimeException, provider BCFIPS not found
    String encodedJWT = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.vPn7xrCNOLWbBRaWdVn53ddj2hW0E87FYl4gPnWy5d1Qj3WgyF8FS6I_hj_3kIJ77tbvy0GXdr7fO91NeWMD1A";
    Verifier verifier = ECVerifier.newVerifier(Paths.get("src/test/resources/ec_public_key_p_256.pem"), new BCFIPSCryptoProvider());
    JWT.getDecoder().decode(encodedJWT, verifier);
  }

  @Test
  public void test_ES256_control() {
    // Control test, known encoded ES256 JWT
    String encodedJWT = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA";

    JWT jwt = JWT.getDecoder().decode(encodedJWT, ECVerifier.newVerifier(
        "-----BEGIN PUBLIC KEY-----\n" +
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9\n" +
        "q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==\n" +
        "-----END PUBLIC KEY-----"));
    assertNotNull(jwt);
    assertEquals(jwt.subject, "1234567890");
    assertEquals(jwt.getString("name"), "John Doe");
    assertEquals(jwt.getBoolean("admin"), Boolean.TRUE);
    assertEquals(jwt.getRawClaims().get("iat"), 1516239022L);
    assertEquals(jwt.issuedAt, ZonedDateTime.ofInstant(Instant.ofEpochSecond(1516239022L), ZoneOffset.UTC));
  }

  @Test
  public void test_ES384() throws Exception {
    String encodedJWT = "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6ImlUcVhYSTB6YkFuSkNLRGFvYmZoa00xZi02ck1TcFRmeVpNUnBfMnRLSTgifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.cJOP_w-hBqnyTsBm3T6lOE5WpcHaAkLuQGAs1QO-lg2eWs8yyGW8p9WagGjxgvx7h9X72H7pXmXqej3GdlVbFmhuzj45A9SXDOAHZ7bJXwM1VidcPi7ZcrsMSCtP1hiN";
    Verifier verifier = ECVerifier.newVerifier(new String(Files.readAllBytes(Paths.get("src/test/resources/ec_public_key_p_384_2.pem"))));
    JWT jwt = JWT.getDecoder().decode(encodedJWT, verifier);
    assertEquals(jwt.subject, "1234567890");
    assertEquals(jwt.getString("name"), "John Doe");
    assertEquals(jwt.getBoolean("admin"), Boolean.TRUE);
    assertEquals(jwt.getRawClaims().get("iat"), 1516239022L);
  }

  @Test
  public void test_ES384_control() {
    // Control test, known encoded ES384 JWT
    String encodedJWT = "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.okIXzSvlJ0gFtnrrcdlzcnYBiJsk-S5m4Qj-qpUSgnT6uMrYIYL06Z7_Nx6buKFyY4DgeS8RU-9tZOy1VmayTbvm0hQyjuiDY8tsoVHi7FhhF4GyTDAAgDH_4jK_h4_R";
    JWT jwt = JWT.getDecoder().decode(encodedJWT, ECVerifier.newVerifier(
        "-----BEGIN PUBLIC KEY-----\n" +
        "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEC1uWSXj2czCDwMTLWV5BFmwxdM6PX9p+\n" +
        "Pk9Yf9rIf374m5XP1U8q79dBhLSIuaojsvOT39UUcPJROSD1FqYLued0rXiooIii\n" +
        "1D3jaW6pmGVJFhodzC31cy5sfOYotrzF\n" +
        "-----END PUBLIC KEY-----"));
    assertNotNull(jwt);
    assertEquals(jwt.subject, "1234567890");
    assertEquals(jwt.getString("name"), "John Doe");
    assertEquals(jwt.getBoolean("admin"), Boolean.TRUE);
    assertEquals(jwt.getRawClaims().get("iat"), 1516239022L);
    assertEquals(jwt.issuedAt, ZonedDateTime.ofInstant(Instant.ofEpochSecond(1516239022L), ZoneOffset.UTC));
  }

  @Test
  public void test_ES512() throws Exception {
    String encodedJWT = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6InhaRGZacHJ5NFA5dlpQWnlHMmZOQlJqLTdMejVvbVZkbTd0SG9DZ1NOZlkifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.AP_CIMClixc5-BFflmjyh_bRrkloEvwzn8IaWJFfMz13X76PGWF0XFuhjJUjp7EYnSAgtjJ-7iJG4IP7w3zGTBk_AUdmvRCiWp5YAe8S_Hcs8e3gkeYoOxiXFZlSSAx0GfwW1cZ0r67mwGtso1I3VXGkSjH5J0Rk6809bn25GoGRjOPu";
    Verifier verifier = ECVerifier.newVerifier(new String(Files.readAllBytes(Paths.get("src/test/resources/ec_public_key_p_521_2.pem"))));
    JWT jwt = JWT.getDecoder().decode(encodedJWT, verifier);
    assertEquals(jwt.subject, "1234567890");
    assertEquals(jwt.getString("name"), "John Doe");
    assertEquals(jwt.getBoolean("admin"), Boolean.TRUE);
    assertEquals(jwt.getRawClaims().get("iat"), 1516239022L);
  }

  @Test
  public void test_ES512_control() {
    // Control test, known encoded ES512 JWT
    String encodedJWT = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.AU5vXkGbPjUABWey3dk4_UldeQMXMwjHY6LG6ff5J-YzH925b4ItQzkJ0kuOuwammUTXRZ7_4W76qa-ooR0umLl1AU0YjFVqxBFXeletCYCznFnIlZYJS-iKqvuwpwPFT0b4OHQxmrIV0ETw4Ei2p1dDMtX4oAbBi-DRybc70CA5f3XT";
    JWT jwt = JWT.getDecoder().decode(encodedJWT, ECVerifier.newVerifier(
        "-----BEGIN PUBLIC KEY-----\n" +
        "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBgc4HZz+/fBbC7lmEww0AO3NK9wVZ\n" +
        "PDZ0VEnsaUFLEYpTzb90nITtJUcPUbvOsdZIZ1Q8fnbquAYgxXL5UgHMoywAib47\n" +
        "6MkyyYgPk0BXZq3mq4zImTRNuaU9slj9TVJ3ScT3L1bXwVuPJDzpr5GOFpaj+WwM\n" +
        "Al8G7CqwoJOsW7Kddns=\n" +
        "-----END PUBLIC KEY-----"));
    assertNotNull(jwt);
    assertEquals(jwt.subject, "1234567890");
    assertEquals(jwt.getString("name"), "John Doe");
    assertEquals(jwt.getBoolean("admin"), Boolean.TRUE);
    assertEquals(jwt.getRawClaims().get("iat"), 1516239022L);
    assertEquals(jwt.issuedAt, ZonedDateTime.ofInstant(Instant.ofEpochSecond(1516239022L), ZoneOffset.UTC));
  }

  @Test
  public void test_ES_2() throws IOException {
    Signer signer = ECSigner.newSHA256Signer(new String(Files.readAllBytes(Paths.get("src/test/resources/ec_private_key_p_256.pem"))));
    Verifier verifier = ECVerifier.newVerifier(new String(Files.readAllBytes(Paths.get("src/test/resources/ec_public_key_p_256.pem"))));

    JWT jwt = new JWT().setSubject("123456789");
    String encodedJWT = JWT.getEncoder().encode(jwt, signer);
    JWT decoded = JWT.getDecoder().decode(encodedJWT, verifier);
    assertNotNull(decoded);
    assertEquals(decoded.subject, "123456789");
  }

  @Test
  public void test_HS256() {
    JWT jwt = new JWT().setSubject("123456789");

    Signer signer = HMACSigner.newSHA256Signer("secret");
    assertEquals(JWT.getEncoder().encode(jwt, signer), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.qHdut1UR4-2FSAvh7U3YdeRR5r5boVqjIGQ16Ztp894");

    signer = HMACSigner.newSHA256Signer("secret".getBytes(StandardCharsets.UTF_8));
    assertEquals(JWT.getEncoder().encode(jwt, signer), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.qHdut1UR4-2FSAvh7U3YdeRR5r5boVqjIGQ16Ztp894");
  }

  @Test
  public void test_HS256_manualAddedClaim() {
    JWT jwt = new JWT().addClaim("test", "123456789");
    Signer signer = HMACSigner.newSHA256Signer("secret");

    assertEquals(JWT.getEncoder().encode(jwt, signer), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoiMTIzNDU2Nzg5In0.0qgr4ztqB0mNXA8mtqaBSL6UJT3aqEyjHMrWDZmT4Bc");
  }

  @Test
  public void test_HS384() {
    JWT jwt = new JWT().setSubject("123456789");

    Signer signer = HMACSigner.newSHA384Signer("secret");
    String encodedJWT = JWT.getEncoder().encode(jwt, signer);
    assertEquals(encodedJWT, "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.sCHKynlQkBveA063_Z-fwcXmRYp_lKQ0fRqGNzplb14qMUj5CV3CfXwluclTF17P");
    assertEquals(JWT.getDecoder().decode(encodedJWT, HMACVerifier.newVerifier("secret")).subject, jwt.subject);

    signer = HMACSigner.newSHA384Signer("secret".getBytes(StandardCharsets.UTF_8));
    encodedJWT = JWT.getEncoder().encode(jwt, signer);
    assertEquals(encodedJWT, "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.sCHKynlQkBveA063_Z-fwcXmRYp_lKQ0fRqGNzplb14qMUj5CV3CfXwluclTF17P");
    assertEquals(JWT.getDecoder().decode(encodedJWT, HMACVerifier.newVerifier("secret")).subject, jwt.subject);
    assertEquals(JWT.getDecoder().decode(encodedJWT, HMACVerifier.newVerifier("secret".getBytes(StandardCharsets.UTF_8))).subject, jwt.subject);
  }

  @Test
  public void test_HS512() {
    JWT jwt = new JWT().setSubject("123456789");

    Signer signer = HMACSigner.newSHA512Signer("secret");
    assertEquals(JWT.getEncoder().encode(jwt, signer), "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.MgAi9gfGkep-IoFYPHMhHz6w2Kxf0u8TZ-wNeQOLPwc8emLNKOMqBU-5dJXeaY5-8wQ1CvZycWHbEilvHgN6Ug");

    signer = HMACSigner.newSHA512Signer("secret".getBytes(StandardCharsets.UTF_8));
    assertEquals(JWT.getEncoder().encode(jwt, signer), "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.MgAi9gfGkep-IoFYPHMhHz6w2Kxf0u8TZ-wNeQOLPwc8emLNKOMqBU-5dJXeaY5-8wQ1CvZycWHbEilvHgN6Ug");
  }

  @Test
  @RequiresAlgorithm("RSASSA-PSS")
  public void test_PS256() throws IOException {
    JWT jwt = new JWT().setSubject("1234567890");

    // Sign the JWT
    Signer signer = RSAPSSSigner.newSHA256Signer(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_private_key_2048.pem"))));
    String encodedJWT = JWT.getEncoder().encode(jwt, signer);

    // Verify the JWT
    Verifier verifier = RSAPSSVerifier.newVerifier(Paths.get("src/test/resources/rsa_public_key_2048.pem"));
    JWT actual = JWT.getDecoder().decode(encodedJWT, verifier);

    assertEquals(actual.subject, jwt.subject);
  }

  @Test
  @RequiresAlgorithm("RSASSA-PSS")
  public void test_PS384() throws IOException {
    JWT jwt = new JWT().setSubject("1234567890");

    // Sign the JWT
    Signer signer = RSAPSSSigner.newSHA384Signer(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_private_key_2048.pem"))));
    String encodedJWT = JWT.getEncoder().encode(jwt, signer);

    // Verify the JWT
    Verifier verifier = RSAPSSVerifier.newVerifier(Paths.get("src/test/resources/rsa_public_key_2048.pem"));
    JWT actual = JWT.getDecoder().decode(encodedJWT, verifier);

    assertEquals(actual.subject, jwt.subject);
  }

  @Test
  @RequiresAlgorithm("RSASSA-PSS")
  public void test_PS512() throws IOException {
    JWT jwt = new JWT().setSubject("1234567890");

    // Sign the JWT
    Signer signer = RSAPSSSigner.newSHA512Signer(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_private_key_3072.pem"))));
    String encodedJWT = JWT.getEncoder().encode(jwt, signer);

    // Verify the JWT
    Verifier verifier = RSAPSSVerifier.newVerifier(Paths.get("src/test/resources/rsa_public_key_3072.pem"));
    JWT actual = JWT.getDecoder().decode(encodedJWT, verifier);

    assertEquals(actual.subject, jwt.subject);
  }

  @Test
  public void test_RS256() throws Exception {
    JWT jwt = new JWT().setSubject("123456789");
    Signer signer = RSASigner.newSHA256Signer(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_private_key_4096.pem"))));

    assertEquals(JWT.getEncoder().encode(jwt, signer), "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.kRXJkOHC98D0LCT2oPg5fTmQJDFXkMRQJopbt7QM6prmQDHwjJL_xO-_EXRXnbvf5NLORto45By3XNn2ZzWmY3pAOxj46MlQ5elhROx2S-EnHZNLfQhoG8ZXPZ54q-Obz_6K7ZSlkAQ8jmeZUO3Ryi8jRlHQ2PT4LbBtLpaf982SGJfeTyUMw1LbvowZUTZSF-E6JARaokmmx8M2GeLuKcFhU-YsBTXUarKp0IJCy3jpMQ2zW_HGjyVWH8WwSIbSdpBn7ztoQEJYO-R5H3qVaAz2BsTuGLRxoyIu1iy2-QcDp5uTufmX1roXM8ciQMpcfwKGiyNpKVIZm-lF8aROXRL4kk4rqp6KUzJuOPljPXRU--xKSua-DeR0BEerKzI9hbwIMWiblCslAciNminoSc9G7pUyVwV5Z5IT8CGJkVgoyVGELeBmYCDy7LHwXrr0poc0hPbE3mJXhzolga4BB84nCg2Hb9tCNiHU8F-rKgZWCONaSSIdhQ49x8OiPafFh2DJBEBe5Xbm6xdCfh3KVG0qe4XL18R5s98aIP9UIC4i62UEgPy6W7Fr7QgUxpXrjRCERBV3MiNu4L8NNJb3oZleq5lQi72EfdS-Bt8ZUOVInIcAvSmu-3i8jB_2sF38XUXdl8gkW8k_b9dJkzDcivCFehvSqGmm3vBm5X4bNmk");
  }

  @Test
  public void test_RS256_BC_FIPS() throws Exception {
    Security.addProvider(new BouncyCastleFipsProvider());
    JWT jwt = new JWT().setSubject("123456789");
    Signer signer = RSASigner.newSHA256Signer(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_private_key_4096.pem"))), new BCFIPSCryptoProvider());

    assertEquals(JWT.getEncoder().encode(jwt, signer), "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.kRXJkOHC98D0LCT2oPg5fTmQJDFXkMRQJopbt7QM6prmQDHwjJL_xO-_EXRXnbvf5NLORto45By3XNn2ZzWmY3pAOxj46MlQ5elhROx2S-EnHZNLfQhoG8ZXPZ54q-Obz_6K7ZSlkAQ8jmeZUO3Ryi8jRlHQ2PT4LbBtLpaf982SGJfeTyUMw1LbvowZUTZSF-E6JARaokmmx8M2GeLuKcFhU-YsBTXUarKp0IJCy3jpMQ2zW_HGjyVWH8WwSIbSdpBn7ztoQEJYO-R5H3qVaAz2BsTuGLRxoyIu1iy2-QcDp5uTufmX1roXM8ciQMpcfwKGiyNpKVIZm-lF8aROXRL4kk4rqp6KUzJuOPljPXRU--xKSua-DeR0BEerKzI9hbwIMWiblCslAciNminoSc9G7pUyVwV5Z5IT8CGJkVgoyVGELeBmYCDy7LHwXrr0poc0hPbE3mJXhzolga4BB84nCg2Hb9tCNiHU8F-rKgZWCONaSSIdhQ49x8OiPafFh2DJBEBe5Xbm6xdCfh3KVG0qe4XL18R5s98aIP9UIC4i62UEgPy6W7Fr7QgUxpXrjRCERBV3MiNu4L8NNJb3oZleq5lQi72EfdS-Bt8ZUOVInIcAvSmu-3i8jB_2sF38XUXdl8gkW8k_b9dJkzDcivCFehvSqGmm3vBm5X4bNmk");
  }

  @Test
  public void test_RS384() throws Exception {
    JWT jwt = new JWT().setSubject("123456789");
    Signer signer = RSASigner.newSHA384Signer(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_private_key_4096.pem"))));

    String encodedJWT = JWT.getEncoder().encode(jwt, signer);
    assertEquals(encodedJWT, "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.OkmWXzhTm7mtfpeMVNLlFjw3fJvc7yMQ1rgI5BXBPqaLSb_fpLHYAq_q5pQDDaIGg8klg9y2f784smc7-o9czX3JnzEDvO9e_sA10YIEA6Q9qRh17EATNXFG-WzSocpxPgEOQZ8lqSqZ_0waCGaUMwK5J5BB1A_70AcNGPnI7PrX76lWNNHwdK0OjkhkxX7vHR6B-uAIzih0ntQP_afr1UIzXkllmnnb1oU9cgFFD1AGDa3V0XCgitVYZA_ozbGELGMrUl_7fB_uNVEvcreUoZIEI4cfUKI6iZ8Ll4j_iLAdlpH4GRGNiQ7gMLq35AqqxKbEG8r-S-SrlRL6PkKlaJ-viMVLxoHreZow634r8A1fxR1mnrdUnn0vGmOthyjpP_TgfAsER9EJ_UUIamsKC8s6pip2jcPB7G6huHocyKBTxsoxclQgk1jOy4lZq4Js2KKM5sGfcq5SWQTW4B44KlUU1kWWmUg21jtflna38sWFdTk845phi5ITOBZ_ElJ9MdYVAgjvDsRFs_XxFENlwpwKeLD9PsaCiJhdG7EJN5qJvVogYuUMM0wyS-SOGZ1ILsTeYsjc7TtI0JUKndlUXFPubwaaxW_06zrCJR-dvWye99fIDH-u3I74XK5MKhknlgewzsXpsiPdvsMW59WUbdIZqkvok5vdkIlm4XGIqcM");

    assertEquals(JWT.getDecoder().decode(encodedJWT, RSAVerifier.newVerifier(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_public_key_4096.pem"))))).subject, jwt.subject);

    // Re-test using a pre-built RSAPublicKey
    assertEquals(JWT.getDecoder().decode(encodedJWT, RSAVerifier.newVerifier((RSAPublicKey) PEM.decode(Paths.get("src/test/resources/rsa_public_key_4096.pem")).getPublicKey())).subject, jwt.subject);
  }

  @Test
  public void test_RS512() throws Exception {
    JWT jwt = new JWT().setSubject("123456789");
    Signer signer = RSASigner.newSHA512Signer(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_private_key_4096.pem"))));

    assertEquals(JWT.getEncoder().encode(jwt, signer), "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.ei28WNoJdUpMlLnHr78HiTnnuKwSRLYcOpgUC3daVInT5RAc0kk2Ipx16Z-bHL_eFLSYgF3TSKdymFpNf8cnEu5T6rH0azYSZLrPmVCetDxjo-ixXK9asPOF3JuIbDjN7ow3K-CMbMCWzWp04ZAh-DNecYEd3HiGgooPVGA4HuVXZFHH8XfQ9TD-64ppBQTWgW32vkna8ILKyIXdwWXSEfCZYfLzLZnilJrz820wZJ5JMXimv2au0OwwRobUMLEBUM4iuEPXLf5wFJU6LcU0XMuovavfIXKDpvP9Yfz6UplMlFvIr9y72xExfaNt32vwneAP-Fpg2x9wYvR0W8LhXKZaFRfcYwhbj17GCAbpx34hjiqnwyFStn5Qx_QHz_Y7ck-ZXB2MGUkiYGj9y_8bQNx-LIaTQUX6sONTNdVVCfnOnMHFqVbupGho24K7885-8BxCRojvA0ggneF6dsKCQvAt2rsVRso0TrCVxwYItb9tRsyhCbWou-zh_08JlYGVXPiGY3RRQDfxCc9RHQUflWRS9CBcPtoaco4mFKZSM-9e_xoYx__DEzM3UjaI4jReLM-IARwlVPoHJa2Vcb5wngZTaxGf2ToMq7R_8KecZymb3OaA2X1e8GS2300ySwsXbOz0sJv2a7_JUncSEBPSsb2vMMurxSJ4E3RTAc4s3aU");
  }

  @Test
  public void test_RSA_1024Key() {
    expectException(InvalidKeyLengthException.class, ()
        -> RSASigner.newSHA256Signer(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_private_key_1024.pem")))));
    expectException(InvalidKeyLengthException.class, ()
        -> RSAVerifier.newVerifier(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_public_key_1024.pem")))));
    expectException(InvalidKeyLengthException.class, ()
        -> RSAVerifier.newVerifier((RSAPublicKey) PEM.decode(Files.readAllBytes(Paths.get("src/test/resources/rsa_public_key_1024.pem"))).getPublicKey()));
  }

  @Test
  public void test_badEncoding() throws Exception {
    Verifier verifier = RSAVerifier.newVerifier(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_public_key_2048.pem"))));
    // add a space to the header, invalid Base64 character point 20 (space)
    expectException(InvalidJWTException.class, ()
        -> JWT.getDecoder().decode("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9 .foo.bar", verifier));
  }

  @Test
  public void test_complexPayload() {
    JWT expectedJWT = new JWT()
        .setAudience(Arrays.asList("www.acme.com", "www.vandelayindustries.com"))
        .setExpiration(ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(60).truncatedTo(ChronoUnit.SECONDS))
        .setIssuedAt(ZonedDateTime.now(ZoneOffset.UTC).truncatedTo(ChronoUnit.SECONDS))
        .setIssuer("www.inversoft.com")
        .setNotBefore(ZonedDateTime.now(ZoneOffset.UTC).minusMinutes(5).truncatedTo(ChronoUnit.SECONDS))
        .setUniqueId(UUID.randomUUID().toString())
        .setSubject("123456789")
        .addClaim("foo", "bar")
        .addClaim("timestamp", 1476062602926L)
        .addClaim("bigInteger", new BigInteger("100000000000000000000000000000000000000000000000000000000000000000000000000000000"))
        .addClaim("bigDecimal", new BigDecimal("11.2398732934908570987534209857423098743209857"))
        .addClaim("double", 3.14d)
        .addClaim("float", 3.14f)
        .addClaim("meaningOfLife", 42)
        .addClaim("bar", Arrays.asList("bing", "bam", "boo"))
        .addClaim("object", Collections.singletonMap("nested", Collections.singletonMap("foo", "bar")))
        .addClaim("www.inversoft.com/claims/is_admin", true);

    Signer signer = HMACSigner.newSHA256Signer("secret");
    Verifier verifier = HMACVerifier.newVerifier("secret");

    String encodedJWT = JWT.getEncoder().encode(expectedJWT, signer, header -> header
        .set("gty", Collections.singletonList("client_credentials"))
        .set("kid", "1234"));
    JWT actualJwt = JWT.getDecoder().decode(encodedJWT, verifier);

    assertEquals(actualJwt.header.algorithm, HMAC.HS256);
    assertEquals(actualJwt.header.type, "JWT");

    // Get manually and with helper.
    assertEquals(actualJwt.header.get("gty"), Collections.singletonList("client_credentials"));
    assertEquals(actualJwt.getHeaderClaim("gty"), Collections.singletonList("client_credentials"));
    // Get manually and with helper.
    assertEquals(actualJwt.header.get("kid"), "1234");
    assertEquals(actualJwt.getHeaderClaim("kid"), "1234");
    // Get missing attribute
    assertNull(actualJwt.header.get("foo"));
    assertNull(actualJwt.getHeaderClaim("foo"));

    assertEquals(actualJwt.audience, expectedJWT.audience);
    assertEquals(actualJwt.expiration, expectedJWT.expiration);
    assertEquals(actualJwt.issuedAt, expectedJWT.issuedAt);
    assertEquals(actualJwt.issuer, expectedJWT.issuer);
    assertEquals(actualJwt.notBefore, expectedJWT.notBefore);
    assertEquals(actualJwt.uniqueId, expectedJWT.uniqueId);
    assertEquals(actualJwt.subject, expectedJWT.subject);
    assertEquals(actualJwt.getString("foo"), expectedJWT.getString("foo"));
    assertEquals(actualJwt.getBigInteger("timestamp"), expectedJWT.getBigInteger("timestamp"));
    assertEquals(actualJwt.getLong("timestamp"), expectedJWT.getLong("timestamp"));
    assertEquals(actualJwt.getNumber("timestamp"), expectedJWT.getNumber("timestamp"));
    assertEquals(actualJwt.getBigInteger("meaningOfLife"), expectedJWT.getBigInteger("meaningOfLife"));
    assertEquals(actualJwt.getInteger("meaningOfLife"), expectedJWT.getInteger("meaningOfLife"));
    assertEquals(actualJwt.getNumber("meaningOfLife"), expectedJWT.getNumber("meaningOfLife"));
    assertEquals(actualJwt.getBigDecimal("double"), expectedJWT.getBigDecimal("double"));
    assertEquals(actualJwt.getDouble("double"), expectedJWT.getDouble("double"));
    assertEquals(actualJwt.getNumber("double"), expectedJWT.getNumber("double"));
    assertEquals(actualJwt.getBigDecimal("float"), expectedJWT.getBigDecimal("float"));
    assertEquals(actualJwt.getFloat("float"), expectedJWT.getFloat("float"));
    assertEquals(actualJwt.getNumber("float"), expectedJWT.getNumber("float"));
    assertEquals(actualJwt.getBigInteger("bigInteger"), expectedJWT.getBigInteger("bigInteger"));
    assertEquals(actualJwt.getNumber("bigInteger"), expectedJWT.getNumber("bigInteger"));
    assertEquals(actualJwt.getBigDecimal("bigDecimal"), expectedJWT.getBigDecimal("bigDecimal"));
    assertEquals(actualJwt.getNumber("bigDecimal"), expectedJWT.getNumber("bigDecimal"));
    assertEquals(actualJwt.getObject("bar"), expectedJWT.getObject("bar"));
    assertEquals(actualJwt.getList("bar"), expectedJWT.getList("bar"));
    assertEquals(actualJwt.getMap("object"), expectedJWT.getObject("object"));
    assertEquals(actualJwt.getBoolean("www.inversoft.com/claims/is_admin"), expectedJWT.getBoolean("www.inversoft.com/claims/is_admin"));

    // validate raw claims
    Map<String, Object> rawClaims = actualJwt.getRawClaims();
    assertEquals(rawClaims.get("aud"), expectedJWT.audience);
    assertEquals(rawClaims.get("exp"), expectedJWT.expiration.toEpochSecond());
    assertEquals(rawClaims.get("iat"), expectedJWT.issuedAt.toEpochSecond());
    assertEquals(rawClaims.get("iss"), expectedJWT.issuer);
    assertEquals(rawClaims.get("nbf"), expectedJWT.notBefore.toEpochSecond());
    assertEquals(rawClaims.get("jti"), expectedJWT.uniqueId);
    assertEquals(rawClaims.get("sub"), expectedJWT.subject);
    assertEquals(rawClaims.get("foo"), expectedJWT.getString("foo"));
    assertEquals(rawClaims.get("timestamp"), expectedJWT.getBigInteger("timestamp"));
    assertEquals(rawClaims.get("meaningOfLife"), expectedJWT.getBigInteger("meaningOfLife"));
    assertEquals(rawClaims.get("bar"), expectedJWT.getObject("bar"));
    assertEquals(rawClaims.get("object"), expectedJWT.getObject("object"));
    assertEquals(rawClaims.get("www.inversoft.com/claims/is_admin"), expectedJWT.getBoolean("www.inversoft.com/claims/is_admin"));

    // validate all claims
    Map<String, Object> allClaims = actualJwt.getAllClaims();
    assertEquals(allClaims.get("aud"), expectedJWT.audience);
    assertEquals(allClaims.get("exp"), expectedJWT.expiration);
    assertEquals(allClaims.get("iat"), expectedJWT.issuedAt);
    assertEquals(allClaims.get("iss"), expectedJWT.issuer);
    assertEquals(allClaims.get("nbf"), expectedJWT.notBefore);
    assertEquals(allClaims.get("jti"), expectedJWT.uniqueId);
    assertEquals(allClaims.get("sub"), expectedJWT.subject);
    assertEquals(allClaims.get("foo"), expectedJWT.getString("foo"));
    assertEquals(allClaims.get("timestamp"), expectedJWT.getBigInteger("timestamp"));
    assertEquals(allClaims.get("meaningOfLife"), expectedJWT.getBigInteger("meaningOfLife"));
    assertEquals(allClaims.get("bar"), expectedJWT.getObject("bar"));
    assertEquals(allClaims.get("object"), expectedJWT.getObject("object"));
    assertEquals(allClaims.get("www.inversoft.com/claims/is_admin"), expectedJWT.getBoolean("www.inversoft.com/claims/is_admin"));
  }

  @Test
  public void test_expiration_clockSkew() {
    JWT expectedJWT = new JWT()
        .setSubject("1234567890")
        .setExpiration(ZonedDateTime.now(ZoneOffset.UTC).minusSeconds(60).truncatedTo(ChronoUnit.SECONDS));

    Signer signer = HMACSigner.newSHA256Signer("secret");
    Verifier verifier = HMACVerifier.newVerifier("secret");

    String encodedJWT = JWT.getEncoder().encode(expectedJWT, signer);

    // Expired still, skew equal to expiration duration minus 1 second
    expectException(JWTExpiredException.class, ()
        -> JWT.getDecoder()
              .withClockSkew(59)
              .decode(encodedJWT, verifier));

    // Expired still, skew equal to expiration duration
    expectException(JWTExpiredException.class, ()
        -> JWT.getDecoder()
              .withClockSkew(60)
              .decode(encodedJWT, verifier));

    // Expired still, use a time machine to modify the 'now' instead of the skew
    expectException(JWTExpiredException.class, ()
        // Provide a 'now' that is 60 seconds in the past.
        -> JWT.getTimeMachineDecoder(ZonedDateTime.now(ZoneOffset.UTC).minusSeconds(60))
              .decode(encodedJWT, verifier));

    // Allow for 61 seconds of skew, ok.
    JWT actual = JWT.getDecoder()
                    .withClockSkew(61)
                    .decode(encodedJWT, verifier);
    assertEquals(actual.subject, "1234567890");

    // Use a time machine to modify the 'now' instead, provide a 'now' that is 61 seconds in the past.
    actual = JWT.getTimeMachineDecoder(ZonedDateTime.now(ZoneOffset.UTC).minusSeconds(61))
                .decode(encodedJWT, verifier);
    assertEquals(actual.subject, "1234567890");
  }

  @Test
  public void test_expiredThrows() {
    JWT expectedJWT = new JWT()
        .setExpiration(ZonedDateTime.now(ZoneOffset.UTC).minusMinutes(1).truncatedTo(ChronoUnit.SECONDS));

    Signer signer = HMACSigner.newSHA256Signer("secret");
    Verifier verifier = HMACVerifier.newVerifier("secret");

    String encodedJWT = JWT.getEncoder().encode(expectedJWT, signer);

    expectException(JWTExpiredException.class, ()
        -> JWT.getDecoder().decode(encodedJWT, verifier));
  }

  @Test
  public void test_external_ec_521() {
    JWT jwt = new JWT()
        .setSubject("1234567890")
        .addClaim("name", "John Doe")
        .addClaim("admin", true)
        .addClaim("iat", 1516239022);

    // PKCS#8 PEM, needs no encapsulation
    Signer signer = ECSigner.newSHA512Signer(
        "-----BEGIN PRIVATE KEY-----\n" +
        "MIHtAgEAMBAGByqGSM49AgEGBSuBBAAjBIHVMIHSAgEBBEHzl1DpZSQJ8YhCbN/u\n" +
        "vo5SOu0BjDDX9Gub6zsBW6B2TxRzb5sBeQaWVscDUZha4Xr1HEWpVtua9+nEQU/9\n" +
        "Aq9Pl6GBiQOBhgAEAJhvCa6S89ePqlLO6MRV9KQqHvdAITDAf/WRDcvCmfrrNuov\n" +
        "+j4gQXO12ohIukPCHM9rYms8Eqciz3gaxVTxZD4CAA8i2k9H6ew9iSh1qXa1kLxi\n" +
        "yzMBqmAmmg4u/SroD6OleG56SwZVbWx+KIINB6r/PQVciGX8FjwgR/mbLHotVZYD\n" +
        "-----END PRIVATE KEY-----");
    String encodedJWT = JWT.getEncoder().encode(jwt, signer, header
        -> header.set("kid", "xZDfZpry4P9vZPZyG2fNBRj-7Lz5omVdm7tHoCgSNfY"));

    Verifier verifier = ECVerifier.newVerifier(
        "-----BEGIN PUBLIC KEY-----\n" +
        "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAmG8JrpLz14+qUs7oxFX0pCoe90Ah\n" +
        "MMB/9ZENy8KZ+us26i/6PiBBc7XaiEi6Q8Icz2tiazwSpyLPeBrFVPFkPgIADyLa\n" +
        "T0fp7D2JKHWpdrWQvGLLMwGqYCaaDi79KugPo6V4bnpLBlVtbH4ogg0Hqv89BVyI\n" +
        "ZfwWPCBH+Zssei1VlgM=\n" +
        "-----END PUBLIC KEY-----");

    JWT actual = JWT.getDecoder().decode(encodedJWT, verifier);
    assertEquals(actual.subject, jwt.subject);

    // Use the function
    actual = JWT.getDecoder().decode(encodedJWT, key -> verifier);
    assertEquals(actual.subject, jwt.subject);
  }

  @Test
  public void test_external_ec_p256() {
    JWT jwt = new JWT()
        .setSubject("1234567890")
        .addClaim("name", "John Doe")
        .addClaim("admin", true)
        .addClaim("iat", 1516239022);

    // PKCS#8 PEM, needs no encapsulation
    Signer signer = ECSigner.newSHA256Signer(
        "-----BEGIN PRIVATE KEY-----\n" +
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgPGJGAm4X1fvBuC1z\n" +
        "SpO/4Izx6PXfNMaiKaS5RUkFqEGhRANCAARCBvmeksd3QGTrVs2eMrrfa7CYF+sX\n" +
        "sjyGg+Bo5mPKGH4Gs8M7oIvoP9pb/I85tdebtKlmiCZHAZE5w4DfJSV6\n" +
        "-----END PRIVATE KEY-----");
    String encodedJWT = JWT.getEncoder().encode(jwt, signer, header
        -> header.set("kid", "xZDfZpry4P9vZPZyG2fNBRj-7Lz5omVdm7tHoCgSNfY"));

    Verifier verifier = ECVerifier.newVerifier(
        "-----BEGIN PUBLIC KEY-----\n" +
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQgb5npLHd0Bk61bNnjK632uwmBfr\n" +
        "F7I8hoPgaOZjyhh+BrPDO6CL6D/aW/yPObXXm7SpZogmRwGROcOA3yUleg==\n" +
        "-----END PUBLIC KEY-----");

    JWT actual = JWT.getDecoder().decode(encodedJWT, verifier);
    assertEquals(actual.subject, jwt.subject);
  }

  @Test
  public void test_external_ec_p384() {
    JWT jwt = new JWT()
        .setSubject("1234567890")
        .addClaim("name", "John Doe")
        .addClaim("admin", true)
        .addClaim("iat", 1516239022);

    // PKCS#8 PEM, needs no encapsulation
    Signer signer = ECSigner.newSHA384Signer(
        "-----BEGIN PRIVATE KEY-----\n" +
        "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCVWQsOJHjKD0I4cXOY\n" +
        "Jm4G8i5c7IMhFbxFq57OUlrTVmND43dvvNW1oQ6i6NiXEQWhZANiAASezSGlAu4w\n" +
        "AaJe4676mQM0F/5slI+EkdptRJdfsQP9mNxe7RdzHgcSw7j/Wxa45nlnFnFrPPL4\n" +
        "viJKOBRxMB1jjVA9my9PixxJGoB22qDQwFbP8ldmEp6abwdBsXNaePM=\n" +
        "-----END PRIVATE KEY-----");
    String encodedJWT = JWT.getEncoder().encode(jwt, signer, header
        -> header.set("kid", "xZDfZpry4P9vZPZyG2fNBRj-7Lz5omVdm7tHoCgSNfY"));

    Verifier verifier = ECVerifier.newVerifier(
        "-----BEGIN PUBLIC KEY-----\n" +
        "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEns0hpQLuMAGiXuOu+pkDNBf+bJSPhJHa\n" +
        "bUSXX7ED/ZjcXu0Xcx4HEsO4/1sWuOZ5ZxZxazzy+L4iSjgUcTAdY41QPZsvT4sc\n" +
        "SRqAdtqg0MBWz/JXZhKemm8HQbFzWnjz\n" +
        "-----END PUBLIC KEY-----");

    JWT actual = JWT.getDecoder().decode(encodedJWT, verifier);
    assertEquals(actual.subject, jwt.subject);

    // Use the function
    actual = JWT.getDecoder().decode(encodedJWT, key -> verifier);
    assertEquals(actual.subject, jwt.subject);
  }

  @Test
  public void test_headerType() {
    String encodedJWT = "eyJhbGciOiJSUzI1NiIsImtpZCI6IkVCQTRGRDNDRUExMDREOTlBODkwODkyNEJBMjNDMEYwIiwidHlwIjoiYXQrand0In0.eyJuYmYiOjE2MDUwMjIwMTUsImV4cCI6MTYwNTAyMjA5MCwiaXNzIjoiaHR0cHM6Ly9kZW1vLmlkZW50aXR5c2VydmVyLmlvIiwiYXVkIjoiYXBpIiwiY2xpZW50X2lkIjoibTJtLnNob3J0IiwianRpIjoiNDUzMTY3N0YwOTg2RTM0NEEyODI4NjVFQ0VBNTM1RjciLCJpYXQiOjE2MDUwMjIwMTUsInNjb3BlIjpbImFwaSJdfQ.qYX88SwfkdexCp_uZ6JeG1k7lJwHZU-Iq8W00P4xsH4MyB8zwkIL2QJ_P8ThfsTYswi1vdD5UJyqC8mbuvJsroq2dhMvml38YU-kunFlnbYoPR_Mah4Y_IZ-Fs48EaYF_kL3PA-0uG7eZDaQHIDBj3vnBdfcdIvfkE_hPzpWE6vLunArvrrMYe2--MkJnyThgqHBxKe2XAV2GfKkkJIceNSfpw8e_cVvc_Y3YVT4uKrURPYcZA_63fI7nHmCWaBvP5K77qzmDciICosp3jhyGUMfy7GzljHqnFDy_S-DHn5OL50DUImpuodKZ5RgFw2-ty7F0SrbEd1OqMhWtMuGcw";
    Header header = JWTUtils.decodeHeader(encodedJWT);
    assertEquals(header.type, "at+jwt");
  }

  @Test
  public void test_loading_keys() throws Exception {
    // Ensure no explosions, loading different ways

    // RSA
    assertNotNull(RSAVerifier.newVerifier(Paths.get("src/test/resources/rsa_public_key_2048.pem")));
    assertNotNull(RSAVerifier.newVerifier(Files.readAllBytes(Paths.get("src/test/resources/rsa_public_key_2048.pem"))));
    assertNotNull(RSAVerifier.newVerifier(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_public_key_2048.pem")))));
    // RSA Verifier can also take a pre-built key
    assertNotNull(RSAVerifier.newVerifier((RSAPublicKey) PEM.decode(Files.readAllBytes(Paths.get("src/test/resources/rsa_public_key_2048.pem"))).getPublicKey()));

    // EC
    assertNotNull(ECVerifier.newVerifier(Paths.get("src/test/resources/ec_public_key_p_256.pem")));
    assertNotNull(ECVerifier.newVerifier(Files.readAllBytes(Paths.get("src/test/resources/ec_public_key_p_256.pem"))));
    assertNotNull(ECVerifier.newVerifier(new String(Files.readAllBytes(Paths.get("src/test/resources/ec_public_key_p_256.pem")))));
    // EC Verifier can also take a pre-built key
    assertNotNull(ECVerifier.newVerifier((ECPublicKey) PEM.decode(Files.readAllBytes(Paths.get("src/test/resources/ec_public_key_p_256.pem"))).getPublicKey()));

    // HMAC
    assertNotNull(HMACVerifier.newVerifier(Paths.get("src/test/resources/secret.txt")));
    assertNotNull(HMACVerifier.newVerifier(Files.readAllBytes(Paths.get("src/test/resources/secret.txt"))));
    assertNotNull(HMACVerifier.newVerifier(new String(Files.readAllBytes(Paths.get("src/test/resources/secret.txt")))));
  }

  @Test
  public void test_multipleSignersAndVerifiers() throws Exception {
    JWT jwt = new JWT().setSubject("123456789");

    // Three separate signers
    Signer signer1 = HMACSigner.newSHA512Signer("secret1");
    Signer signer2 = HMACSigner.newSHA512Signer("secret2");
    Signer signer3 = RSASigner.newSHA256Signer(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_private_key_2048.pem"))));

    // Encode the same JWT with each signer, writing the Key ID to the header
    String encodedJWT1 = JWT.getEncoder().encode(jwt, signer1, h -> h.set("kid", "verifier1"));
    String encodedJWT2 = JWT.getEncoder().encode(jwt, signer2, h -> h.set("kid", "verifier2"));
    String encodedJWT3 = JWT.getEncoder().encode(jwt, signer3, h -> h.set("kid", "verifier3"));

    Verifier verifier1 = HMACVerifier.newVerifier("secret1");
    Verifier verifier2 = HMACVerifier.newVerifier("secret2");
    Verifier verifier3 = RSAVerifier.newVerifier(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_public_key_2048.pem"))));

    Map<String, Verifier> verifiers = new HashMap<>();
    verifiers.put("verifier1", verifier1);
    verifiers.put("verifier2", verifier2);
    verifiers.put("verifier3", verifier3);

    // decode all of the encoded JWTs and ensure they come out the same.
    JWT jwt1 = JWT.getDecoder().decode(encodedJWT1, verifiers);
    JWT jwt2 = JWT.getDecoder().decode(encodedJWT2, verifiers);
    JWT jwt3 = JWT.getDecoder().decode(encodedJWT3, verifiers);

    assertEquals(jwt1.subject, jwt2.subject);
    assertEquals(jwt2.subject, jwt3.subject);
  }

  @Test
  public void test_notBeforeThrows() {
    JWT expectedJWT = new JWT()
        .setExpiration(ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(60).truncatedTo(ChronoUnit.SECONDS))
        .setIssuedAt(ZonedDateTime.now(ZoneOffset.UTC).truncatedTo(ChronoUnit.SECONDS))
        .setIssuer("www.inversoft.com")
        .setNotBefore(ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(5).truncatedTo(ChronoUnit.SECONDS));

    Signer signer = HMACSigner.newSHA256Signer("secret");
    Verifier verifier = HMACVerifier.newVerifier("secret");

    String encodedJWT = JWT.getEncoder().encode(expectedJWT, signer);

    expectException(JWTUnavailableForProcessingException.class, ()
        -> JWT.getDecoder().decode(encodedJWT, verifier));
  }

  @Test
  public void test_notBefore_clockSkew() {
    JWT expectedJWT = new JWT()
        .setSubject("1234567890")
        .setNotBefore(ZonedDateTime.now(ZoneOffset.UTC).plusSeconds(60).truncatedTo(ChronoUnit.SECONDS))
        .setExpiration(ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(5).truncatedTo(ChronoUnit.SECONDS));

    Signer signer = HMACSigner.newSHA256Signer("secret");
    Verifier verifier = HMACVerifier.newVerifier("secret");

    String encodedJWT = JWT.getEncoder().encode(expectedJWT, signer);

    // Not allowed to be used until 60 seconds from now, skew equal to future availability minus 1 second
    expectException(JWTUnavailableForProcessingException.class, ()
        -> JWT.getDecoder()
              .withClockSkew(59)
              .decode(encodedJWT, verifier));

    // Not allowed to be used until 60 seconds from now, skew equal to future availability minus 1 second
    // - Use a time machine to change 'now'
    expectException(JWTUnavailableForProcessingException.class, ()
        // Provide a 'now' that is 59 seconds in the future
        -> JWT.getTimeMachineDecoder(ZonedDateTime.now(ZoneOffset.UTC).plusSeconds(59))
              .decode(encodedJWT, verifier));

    // Allow for 60 seconds of skew, ok.
    JWT actual = JWT.getDecoder()
                    .withClockSkew(60)
                    .decode(encodedJWT, verifier);
    assertEquals(actual.subject, "1234567890");

    // Use a time machine to modify the 'now' instead of the skew
    actual = JWT.getTimeMachineDecoder(ZonedDateTime.now(ZoneOffset.UTC).plusSeconds(60))
                .decode(encodedJWT, verifier);
    assertEquals(actual.subject, "1234567890");
  }

  @Test
  public void test_nullFailFast() {
    expectException(NullPointerException.class, () -> new JWTDecoder().decode(null));
    expectException(NullPointerException.class, () -> new JWTDecoder().decode(null, null, null, null));
    expectException(NullPointerException.class, () -> new JWTDecoder().decode("foo", Collections.emptyMap(), null));
    expectException(NullPointerException.class, () -> new JWTDecoder().decode("foo", key -> null, null));
    expectException(NullPointerException.class, () -> new JWTDecoder().decode("foo", key -> null, null));
  }

  @Test
  public void test_openssl_keys_p_256() {
    JWT jwt = new JWT()
        .setSubject("1234567890")
        .addClaim("name", "John Doe")
        .addClaim("admin", true)
        .addClaim("iat", 1516239022);

    // PKCS#8 PEM, needs no encapsulation
    Signer signer = ECSigner.newSHA256Signer(
        "-----BEGIN PRIVATE KEY-----\n" +
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgy3F4UN/uqaNn4o4G\n" +
        "8UHT3Gq6Ab/2CdjFeoDpLREcGaChRANCAAR2dqbsTukFi1nBHI4wOOApeczUf8pG\n" +
        "8g+hsTDTedkDj4q9686mgx+OwHwbT5XOt+sNEhyz0jxUz6Vy+6l6DeUQ\n" +
        "-----END PRIVATE KEY-----");
    String encodedJWT = JWT.getEncoder().encode(jwt, signer, header
        -> header.set("kid", "xZDfZpry4P9vZPZyG2fNBRj-7Lz5omVdm7tHoCgSNfY"));

    Verifier verifier = ECVerifier.newVerifier(
        "-----BEGIN PUBLIC KEY-----\n" +
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdnam7E7pBYtZwRyOMDjgKXnM1H/K\n" +
        "RvIPobEw03nZA4+KvevOpoMfjsB8G0+VzrfrDRIcs9I8VM+lcvupeg3lEA==\n" +
        "-----END PUBLIC KEY-----");

    JWT actual = JWT.getDecoder().decode(encodedJWT, verifier);
    assertEquals(actual.subject, jwt.subject);
  }

  @Test
  public void test_openssl_keys_p_521() {
    JWT jwt = new JWT()
        .setSubject("1234567890")
        .addClaim("name", "John Doe")
        .addClaim("admin", true)
        .addClaim("iat", 1516239022);

    // PKCS#8 PEM, needs no encapsulation
    Signer signer = ECSigner.newSHA512Signer(
        "-----BEGIN PRIVATE KEY-----\n" +
        "MIHtAgEAMBAGByqGSM49AgEGBSuBBAAjBIHVMIHSAgEBBEHdgM7Q2N5VAu1JXri9\n" +
        "5AYmCZo+rVbdtYbz58D0mWB+TZs8YPvawg6u3m1xGNJXoqPBr/KSVvqHkpgLONlU\n" +
        "NGs5t6GBiQOBhgAEAYsJ/uVsOJR5FrCynbKsuWhkj/+2PdFnIlnJp1s0l0T13gtE\n" +
        "iIcpzSDLHuvJS3812NlC5ZYGvhqIoWfMBy4KTfdyAenIeyriM/P6gJeR1HYMZIP0\n" +
        "PFNr0EghmYCIK51MamQAlEcvhoPri1phF6Fa6mZtrCqaaIB3VDNRaabcJfsFHl94\n" +
        "-----END PRIVATE KEY-----");
    String encodedJWT = JWT.getEncoder().encode(jwt, signer, header
        -> header.set("kid", "xZDfZpry4P9vZPZyG2fNBRj-7Lz5omVdm7tHoCgSNfY"));

    Verifier verifier = ECVerifier.newVerifier(
        "-----BEGIN PUBLIC KEY-----\n" +
        "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBiwn+5Ww4lHkWsLKdsqy5aGSP/7Y9\n" +
        "0WciWcmnWzSXRPXeC0SIhynNIMse68lLfzXY2ULllga+GoihZ8wHLgpN93IB6ch7\n" +
        "KuIz8/qAl5HUdgxkg/Q8U2vQSCGZgIgrnUxqZACURy+Gg+uLWmEXoVrqZm2sKppo\n" +
        "gHdUM1Fpptwl+wUeX3g=\n" +
        "-----END PUBLIC KEY-----");
    JWT actual = JWT.getDecoder().decode(encodedJWT, verifier);
    assertEquals(actual.subject, jwt.subject);
  }

  @Test
  public void test_zonedDateTime() {
    ZonedDateTime expiration = ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(60).truncatedTo(ChronoUnit.SECONDS);
    JWT expectedJWT = new JWT().setExpiration(expiration);

    Signer signer = HMACSigner.newSHA256Signer("secret");
    Verifier verifier = HMACVerifier.newVerifier("secret");

    String encodedJWT1 = JWT.getEncoder().encode(expectedJWT, signer);
    JWT actualJWT1 = JWT.getDecoder().decode(encodedJWT1, verifier);

    assertEquals(actualJWT1.expiration, expectedJWT.expiration);
  }
}
