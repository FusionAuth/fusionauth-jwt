/*
 * Copyright (c) 2016-2018, Inversoft Inc., All Rights Reserved
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

package org.primeframework.jwt;

import org.primeframework.jwt.domain.InvalidJWTException;
import org.primeframework.jwt.domain.InvalidJWTSignatureException;
import org.primeframework.jwt.domain.InvalidKeyLengthException;
import org.primeframework.jwt.domain.JWT;
import org.primeframework.jwt.domain.JWTExpiredException;
import org.primeframework.jwt.domain.JWTUnavailableForProcessingException;
import org.primeframework.jwt.domain.MissingVerifierException;
import org.primeframework.jwt.hmac.HMACSigner;
import org.primeframework.jwt.hmac.HMACVerifier;
import org.primeframework.jwt.rsa.RSASigner;
import org.primeframework.jwt.rsa.RSAVerifier;
import org.testng.annotations.Test;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * @author Daniel DeGroff
 */
public class JWTTest {

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
    String secret = JWTUtils.generateSHA256HMACSecret();
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

      System.out.println("[" + signer.getAlgorithm().getName() + "] " + duration.toMillis() + " milliseconds total. [" + iterationCount + "] iterations. [" + average + "] milliseconds per iteration. Approx. [" + perSecond + "] per second.");

    }
  }

  @Test(enabled = false)
  public void encoding_performance() throws Exception {
    Signer hmacSigner = HMACSigner.newSHA256Signer(JWTUtils.generateSHA256HMACSecret());
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

      System.out.println("[" + signer.getAlgorithm().getName() + "] " + duration.toMillis() + " milliseconds total. [" + iterationCount + "] iterations. [" + average + "] milliseconds per iteration. Approx. [" + perSecond + "] per second.");
    }
  }

  @Test
  public void expired() throws Exception {
    // no expiration
    assertFalse(new JWT()
        .setSubject("123456789").isExpired());

    assertFalse(new JWT()
        .setExpiration(ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(1))
        .setSubject("123456789").isExpired());

    assertTrue(new JWT()
        .setExpiration(ZonedDateTime.now(ZoneOffset.UTC).minusMinutes(1))
        .setSubject("123456789").isExpired());
  }

  @Test
  public void test_HS256() throws Exception {
    JWT jwt = new JWT().setSubject("123456789");
    Signer signer = HMACSigner.newSHA256Signer("secret");

    assertEquals(JWT.getEncoder().encode(jwt, signer), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.qHdut1UR4-2FSAvh7U3YdeRR5r5boVqjIGQ16Ztp894");
  }

  @Test
  public void test_HS256_manualAddedClaim() throws Exception {
    JWT jwt = new JWT().addClaim("test", "123456789");
    Signer signer = HMACSigner.newSHA256Signer("secret");

    assertEquals(JWT.getEncoder().encode(jwt, signer), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoiMTIzNDU2Nzg5In0.0qgr4ztqB0mNXA8mtqaBSL6UJT3aqEyjHMrWDZmT4Bc");
  }

  @Test
  public void test_HS384() throws Exception {
    JWT jwt = new JWT().setSubject("123456789");
    Signer signer = HMACSigner.newSHA384Signer("secret");

    String encodedJWT = JWT.getEncoder().encode(jwt, signer);
    assertEquals(encodedJWT, "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.sCHKynlQkBveA063_Z-fwcXmRYp_lKQ0fRqGNzplb14qMUj5CV3CfXwluclTF17P");

    assertEquals(JWT.getDecoder().decode(encodedJWT, HMACVerifier.newVerifier("secret")).subject, jwt.subject);
  }

  @Test
  public void test_HS512() throws Exception {
    JWT jwt = new JWT().setSubject("123456789");
    Signer signer = HMACSigner.newSHA512Signer("secret");

    assertEquals(JWT.getEncoder().encode(jwt, signer), "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.MgAi9gfGkep-IoFYPHMhHz6w2Kxf0u8TZ-wNeQOLPwc8emLNKOMqBU-5dJXeaY5-8wQ1CvZycWHbEilvHgN6Ug");
  }

  @Test
  public void test_RS256() throws Exception {
    JWT jwt = new JWT().setSubject("123456789");
    Signer signer = RSASigner.newSHA256Signer(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_private_key_4096.pem"))));

    assertEquals(JWT.getEncoder().encode(jwt, signer), "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.kRXJkOHC98D0LCT2oPg5fTmQJDFXkMRQJopbt7QM6prmQDHwjJL_xO-_EXRXnbvf5NLORto45By3XNn2ZzWmY3pAOxj46MlQ5elhROx2S-EnHZNLfQhoG8ZXPZ54q-Obz_6K7ZSlkAQ8jmeZUO3Ryi8jRlHQ2PT4LbBtLpaf982SGJfeTyUMw1LbvowZUTZSF-E6JARaokmmx8M2GeLuKcFhU-YsBTXUarKp0IJCy3jpMQ2zW_HGjyVWH8WwSIbSdpBn7ztoQEJYO-R5H3qVaAz2BsTuGLRxoyIu1iy2-QcDp5uTufmX1roXM8ciQMpcfwKGiyNpKVIZm-lF8aROXRL4kk4rqp6KUzJuOPljPXRU--xKSua-DeR0BEerKzI9hbwIMWiblCslAciNminoSc9G7pUyVwV5Z5IT8CGJkVgoyVGELeBmYCDy7LHwXrr0poc0hPbE3mJXhzolga4BB84nCg2Hb9tCNiHU8F-rKgZWCONaSSIdhQ49x8OiPafFh2DJBEBe5Xbm6xdCfh3KVG0qe4XL18R5s98aIP9UIC4i62UEgPy6W7Fr7QgUxpXrjRCERBV3MiNu4L8NNJb3oZleq5lQi72EfdS-Bt8ZUOVInIcAvSmu-3i8jB_2sF38XUXdl8gkW8k_b9dJkzDcivCFehvSqGmm3vBm5X4bNmk");
  }

  @Test
  public void test_RS384() throws Exception {
    JWT jwt = new JWT().setSubject("123456789");
    Signer signer = RSASigner.newSHA384Signer(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_private_key_4096.pem"))));

    String encodedJWT = JWT.getEncoder().encode(jwt, signer);
    assertEquals(encodedJWT, "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.OkmWXzhTm7mtfpeMVNLlFjw3fJvc7yMQ1rgI5BXBPqaLSb_fpLHYAq_q5pQDDaIGg8klg9y2f784smc7-o9czX3JnzEDvO9e_sA10YIEA6Q9qRh17EATNXFG-WzSocpxPgEOQZ8lqSqZ_0waCGaUMwK5J5BB1A_70AcNGPnI7PrX76lWNNHwdK0OjkhkxX7vHR6B-uAIzih0ntQP_afr1UIzXkllmnnb1oU9cgFFD1AGDa3V0XCgitVYZA_ozbGELGMrUl_7fB_uNVEvcreUoZIEI4cfUKI6iZ8Ll4j_iLAdlpH4GRGNiQ7gMLq35AqqxKbEG8r-S-SrlRL6PkKlaJ-viMVLxoHreZow634r8A1fxR1mnrdUnn0vGmOthyjpP_TgfAsER9EJ_UUIamsKC8s6pip2jcPB7G6huHocyKBTxsoxclQgk1jOy4lZq4Js2KKM5sGfcq5SWQTW4B44KlUU1kWWmUg21jtflna38sWFdTk845phi5ITOBZ_ElJ9MdYVAgjvDsRFs_XxFENlwpwKeLD9PsaCiJhdG7EJN5qJvVogYuUMM0wyS-SOGZ1ILsTeYsjc7TtI0JUKndlUXFPubwaaxW_06zrCJR-dvWye99fIDH-u3I74XK5MKhknlgewzsXpsiPdvsMW59WUbdIZqkvok5vdkIlm4XGIqcM");

    assertEquals(JWT.getDecoder().decode(encodedJWT, RSAVerifier.newVerifier(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_public_key_4096.pem"))))).subject, jwt.subject);
  }

  @Test
  public void test_RS512() throws Exception {
    JWT jwt = new JWT().setSubject("123456789");
    Signer signer = RSASigner.newSHA512Signer(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_private_key_4096.pem"))));

    assertEquals(JWT.getEncoder().encode(jwt, signer), "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.ei28WNoJdUpMlLnHr78HiTnnuKwSRLYcOpgUC3daVInT5RAc0kk2Ipx16Z-bHL_eFLSYgF3TSKdymFpNf8cnEu5T6rH0azYSZLrPmVCetDxjo-ixXK9asPOF3JuIbDjN7ow3K-CMbMCWzWp04ZAh-DNecYEd3HiGgooPVGA4HuVXZFHH8XfQ9TD-64ppBQTWgW32vkna8ILKyIXdwWXSEfCZYfLzLZnilJrz820wZJ5JMXimv2au0OwwRobUMLEBUM4iuEPXLf5wFJU6LcU0XMuovavfIXKDpvP9Yfz6UplMlFvIr9y72xExfaNt32vwneAP-Fpg2x9wYvR0W8LhXKZaFRfcYwhbj17GCAbpx34hjiqnwyFStn5Qx_QHz_Y7ck-ZXB2MGUkiYGj9y_8bQNx-LIaTQUX6sONTNdVVCfnOnMHFqVbupGho24K7885-8BxCRojvA0ggneF6dsKCQvAt2rsVRso0TrCVxwYItb9tRsyhCbWou-zh_08JlYGVXPiGY3RRQDfxCc9RHQUflWRS9CBcPtoaco4mFKZSM-9e_xoYx__DEzM3UjaI4jReLM-IARwlVPoHJa2Vcb5wngZTaxGf2ToMq7R_8KecZymb3OaA2X1e8GS2300ySwsXbOz0sJv2a7_JUncSEBPSsb2vMMurxSJ4E3RTAc4s3aU");
  }

  @Test
  public void test_RSA_1024Key() throws Exception {
    expectException(InvalidKeyLengthException.class, ()
        -> RSASigner.newSHA256Signer(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_private_key_1024.pem")))));
    expectException(InvalidKeyLengthException.class, ()
        -> RSAVerifier.newVerifier(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_public_key_1024.pem")))));
  }

  @Test
  public void test_SingedWithoutSignature() throws Exception {
    JWT inputJwt = new JWT()
        .setSubject("123456789")
        .setIssuedAt(ZonedDateTime.now(ZoneOffset.UTC))
        .setExpiration(ZonedDateTime.now(ZoneOffset.UTC).plusHours(2));

    String encodedJWT = JWT.getEncoder().encode(inputJwt, HMACSigner.newSHA256Signer("secret"));
    String encodedJWTNoSignature = encodedJWT.substring(0, encodedJWT.lastIndexOf('.') + 1);

    expectException(InvalidJWTSignatureException.class, () -> JWT.getDecoder().decode(encodedJWTNoSignature, HMACVerifier.newVerifier("secret")));

    // Also cannot be decoded even if the caller calls decode w/out a signature because the header still indicates a signature algorithm.
    expectException(InvalidJWTSignatureException.class, () -> JWT.getDecoder().decode(encodedJWTNoSignature));
  }

  @Test
  public void test_badEncoding() throws Exception {
    Verifier verifier = RSAVerifier.newVerifier(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_public_key_2048.pem"))));
    // add a space to the header, invalid Base64 character point 20 (space)
    expectException(InvalidJWTException.class, ()
        -> JWT.getDecoder().decode("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9 .foo.bar", verifier));
  }

  @Test
  public void test_complexPayload() throws Exception {
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
        .addClaim("meaningOfLife", 42)
        .addClaim("bar", Arrays.asList("bing", "bam", "boo"))
        .addClaim("www.inversoft.com/claims/is_admin", true);

    Signer signer = HMACSigner.newSHA256Signer("secret");
    Verifier verifier = HMACVerifier.newVerifier("secret");

    String encodedJWT = JWT.getEncoder().encode(expectedJWT, signer);
    JWT actualJwt = JWT.getDecoder().decode(encodedJWT, verifier);

    assertEquals(actualJwt.audience, expectedJWT.audience);
    assertEquals(actualJwt.expiration, expectedJWT.expiration);
    assertEquals(actualJwt.issuedAt, expectedJWT.issuedAt);
    assertEquals(actualJwt.issuer, expectedJWT.issuer);
    assertEquals(actualJwt.notBefore, expectedJWT.notBefore);
    assertEquals(actualJwt.uniqueId, expectedJWT.uniqueId);
    assertEquals(actualJwt.subject, expectedJWT.subject);
    assertEquals(actualJwt.getString("foo"), expectedJWT.getString("foo"));
    assertEquals(actualJwt.getLong("timestamp"), expectedJWT.getLong("timestamp"));
    assertEquals(actualJwt.getInteger("meaningOfLife"), expectedJWT.getInteger("meaningOfLife"));
    assertEquals(actualJwt.getObject("bar"), expectedJWT.getObject("bar"));
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
    assertEquals(rawClaims.get("timestamp"), expectedJWT.getLong("timestamp"));
    assertEquals(rawClaims.get("meaningOfLife"), expectedJWT.getInteger("meaningOfLife"));
    assertEquals(rawClaims.get("bar"), expectedJWT.getObject("bar"));
    assertEquals(rawClaims.get("www.inversoft.com/claims/is_admin"), expectedJWT.getBoolean("www.inversoft.com/claims/is_admin"));
  }

  @Test
  public void test_encodedJwtWithSignatureRemoved() throws Exception {
    // Sign a JWT and then attempt to verify it using None.
    JWT jwt = new JWT().setSubject("art");
    String encodedJWT = JWT.getEncoder().encode(jwt, HMACSigner.newSHA256Signer("secret"));

    String hackedJWT = encodedJWT.substring(0, encodedJWT.lastIndexOf("."));

    expectException(InvalidJWTException.class, ()
        -> JWT.getDecoder().decode(hackedJWT, HMACVerifier.newVerifier("secret")));
  }

  @Test
  public void test_expiredThrows() throws Exception {
    JWT expectedJWT = new JWT()
        .setExpiration(ZonedDateTime.now(ZoneOffset.UTC).minusMinutes(1).truncatedTo(ChronoUnit.SECONDS));

    Signer signer = HMACSigner.newSHA256Signer("secret");
    Verifier verifier = HMACVerifier.newVerifier("secret");

    String encodedJWT = JWT.getEncoder().encode(expectedJWT, signer);

    expectException(JWTExpiredException.class, ()
        -> JWT.getDecoder().decode(encodedJWT, verifier));
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
  public void test_noVerification() throws Exception {
    // Sign a JWT and then attempt to verify it using None.
    JWT jwt = new JWT().setSubject("art");
    String encodedJWT = JWT.getEncoder().encode(jwt, HMACSigner.newSHA256Signer("secret"));

    expectException(MissingVerifierException.class, ()
        -> JWT.getDecoder().decode(encodedJWT));
  }

  @Test
  public void test_none() throws Exception {
    JWT jwt = new JWT().setSubject("123456789");
    Signer signer = new UnsecuredSigner();

    String encodedJWT = JWT.getEncoder().encode(jwt, signer);
    assertEquals(encodedJWT, "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkifQ.");

    JWT actual = JWT.getDecoder().decode(encodedJWT);
    assertEquals(actual.subject, jwt.subject);
  }

  @Test
  public void test_notBeforeThrows() throws Exception {
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
  public void test_zonedDateTime() throws Exception {
    ZonedDateTime expiration = ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(60).truncatedTo(ChronoUnit.SECONDS);
    JWT expectedJWT = new JWT().setExpiration(expiration);

    Signer signer = HMACSigner.newSHA256Signer("secret");
    Verifier verifier = HMACVerifier.newVerifier("secret");

    String encodedJWT1 = JWT.getEncoder().encode(expectedJWT, signer);
    JWT actualJWT1 = JWT.getDecoder().decode(encodedJWT1, verifier);

    assertEquals(actualJWT1.expiration, expectedJWT.expiration);
  }

  private void expectException(Class<? extends Exception> expected, ThrowingRunnable runnable) {
    try {
      runnable.run();
      fail("Expected [" + expected.getCanonicalName() + "] to be thrown. No Exception was thrown.");
    } catch (Exception e) {
      if (!e.getClass().isAssignableFrom(expected)) {
        fail("Expected [" + expected.getCanonicalName() + "] to be thrown. Caught this instead [" + e.getClass().getCanonicalName() + "]");
      }
    }
  }

  private interface ThrowingRunnable {
    void run() throws Exception;
  }
}
