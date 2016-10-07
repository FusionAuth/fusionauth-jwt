/*
 * Copyright (c) 2016, Inversoft Inc., All Rights Reserved
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

import org.primeframework.jwt.domain.Algorithm;
import org.primeframework.jwt.domain.JWT;
import org.primeframework.jwt.hmac.HmacSigner;
import org.primeframework.jwt.hmac.HmacVerifier;
import org.primeframework.jwt.rsa.RSASigner;
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
import java.util.Arrays;

import static org.testng.Assert.assertEquals;

/**
 * @author Daniel DeGroff
 */
public class JWTTest {

  @Test(enabled = false)
  public void encoding_performance() throws Exception {
    Signer hmacSigner = new HmacSigner(Algorithm.HS256, "secret");
    Signer rsaSigner = new RSASigner(Algorithm.RS256, new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_private_key_4096"))));
    JWT jwt = new JWT().with(t -> t.subject = "123456789");

    long iterationCount = 500;
    for (Signer signer : Arrays.asList(hmacSigner, rsaSigner)) {
      Instant start = Instant.now();
      for (int i = 0; i < iterationCount; i++) {
        JWT.getEncoder().encode(jwt, signer);
      }
      Duration duration = Duration.between(start, Instant.now());
      BigDecimal durationInMillis = BigDecimal.valueOf(duration.toMillis());
      BigDecimal average = durationInMillis.divide(BigDecimal.valueOf(iterationCount), RoundingMode.HALF_DOWN);
      float perSecond = 1000F / average.floatValue();

      // HMAC 256 ~ 100,000+ per iterations per second (once the VM warms up, this is very fast)
      // RSA w/ 4k Key ~ 20 iterations per second (this seems to be fairly linear)
      System.out.println("[" + signer.getAlgorithm().getName() + "] " + duration.toMillis() + " milliseconds total. [" + iterationCount + "] iterations. [" + average + "] milliseconds per iteration. Approx. [" + perSecond + "] per second.");
    }
  }

  @Test
  public void test_HS256() throws Exception {
    JWT jwt = new JWT().with(t -> t.subject = "123456789");
    Signer signer = new HmacSigner(Algorithm.HS256, "secret");

    assertEquals(JWT.getEncoder().encode(jwt, signer), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.qHdut1UR4-2FSAvh7U3YdeRR5r5boVqjIGQ16Ztp894");
  }

  @Test
  public void test_HS256_manualAddedClaim() throws Exception {
    JWT jwt = new JWT().withClaim("test", "123456789");
    Signer signer = new HmacSigner(Algorithm.HS256, "secret");

    assertEquals(JWT.getEncoder().encode(jwt, signer), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoiMTIzNDU2Nzg5In0.0qgr4ztqB0mNXA8mtqaBSL6UJT3aqEyjHMrWDZmT4Bc");
  }

  @Test
  public void test_HS512() throws Exception {
    JWT jwt = new JWT().with(t -> t.subject = "123456789");
    Signer signer = new HmacSigner(Algorithm.HS512, "secret");

    assertEquals(JWT.getEncoder().encode(jwt, signer), "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.MgAi9gfGkep-IoFYPHMhHz6w2Kxf0u8TZ-wNeQOLPwc8emLNKOMqBU-5dJXeaY5-8wQ1CvZycWHbEilvHgN6Ug");
  }

  @Test
  public void test_RS256() throws Exception {
    JWT jwt = new JWT().with(t -> t.subject = "123456789");
    Signer signer = new RSASigner(Algorithm.RS256, new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_private_key_4096"))));

    assertEquals(JWT.getEncoder().encode(jwt, signer), "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.kRXJkOHC98D0LCT2oPg5fTmQJDFXkMRQJopbt7QM6prmQDHwjJL_xO-_EXRXnbvf5NLORto45By3XNn2ZzWmY3pAOxj46MlQ5elhROx2S-EnHZNLfQhoG8ZXPZ54q-Obz_6K7ZSlkAQ8jmeZUO3Ryi8jRlHQ2PT4LbBtLpaf982SGJfeTyUMw1LbvowZUTZSF-E6JARaokmmx8M2GeLuKcFhU-YsBTXUarKp0IJCy3jpMQ2zW_HGjyVWH8WwSIbSdpBn7ztoQEJYO-R5H3qVaAz2BsTuGLRxoyIu1iy2-QcDp5uTufmX1roXM8ciQMpcfwKGiyNpKVIZm-lF8aROXRL4kk4rqp6KUzJuOPljPXRU--xKSua-DeR0BEerKzI9hbwIMWiblCslAciNminoSc9G7pUyVwV5Z5IT8CGJkVgoyVGELeBmYCDy7LHwXrr0poc0hPbE3mJXhzolga4BB84nCg2Hb9tCNiHU8F-rKgZWCONaSSIdhQ49x8OiPafFh2DJBEBe5Xbm6xdCfh3KVG0qe4XL18R5s98aIP9UIC4i62UEgPy6W7Fr7QgUxpXrjRCERBV3MiNu4L8NNJb3oZleq5lQi72EfdS-Bt8ZUOVInIcAvSmu-3i8jB_2sF38XUXdl8gkW8k_b9dJkzDcivCFehvSqGmm3vBm5X4bNmk");
  }

  @Test
  public void test_RS512() throws Exception {
    JWT jwt = new JWT().with(t -> t.subject = "123456789");
    Signer signer = new RSASigner(Algorithm.RS512, new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_private_key_4096"))));

    assertEquals(JWT.getEncoder().encode(jwt, signer), "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.ei28WNoJdUpMlLnHr78HiTnnuKwSRLYcOpgUC3daVInT5RAc0kk2Ipx16Z-bHL_eFLSYgF3TSKdymFpNf8cnEu5T6rH0azYSZLrPmVCetDxjo-ixXK9asPOF3JuIbDjN7ow3K-CMbMCWzWp04ZAh-DNecYEd3HiGgooPVGA4HuVXZFHH8XfQ9TD-64ppBQTWgW32vkna8ILKyIXdwWXSEfCZYfLzLZnilJrz820wZJ5JMXimv2au0OwwRobUMLEBUM4iuEPXLf5wFJU6LcU0XMuovavfIXKDpvP9Yfz6UplMlFvIr9y72xExfaNt32vwneAP-Fpg2x9wYvR0W8LhXKZaFRfcYwhbj17GCAbpx34hjiqnwyFStn5Qx_QHz_Y7ck-ZXB2MGUkiYGj9y_8bQNx-LIaTQUX6sONTNdVVCfnOnMHFqVbupGho24K7885-8BxCRojvA0ggneF6dsKCQvAt2rsVRso0TrCVxwYItb9tRsyhCbWou-zh_08JlYGVXPiGY3RRQDfxCc9RHQUflWRS9CBcPtoaco4mFKZSM-9e_xoYx__DEzM3UjaI4jReLM-IARwlVPoHJa2Vcb5wngZTaxGf2ToMq7R_8KecZymb3OaA2X1e8GS2300ySwsXbOz0sJv2a7_JUncSEBPSsb2vMMurxSJ4E3RTAc4s3aU");
  }

  @Test
  public void test_complexPayload() throws Exception {
    JWT expectedJwt = new JWT()
        .with(t -> t.audience = Arrays.asList("www.acme.com", "www.vandelayindustries.com"))
        .with(t -> t.expiration = ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(60).truncatedTo(ChronoUnit.SECONDS))
        .with(t -> t.issuedAt = ZonedDateTime.now(ZoneOffset.UTC).truncatedTo(ChronoUnit.SECONDS))
        .with(t -> t.issuer = "www.inversoft.com")
        .with(t -> t.subject = "123456789")
        .withClaim("foo", "bar")
        .withClaim("bar", Arrays.asList("bing", "bam", "boo"))
        .withClaim("www.inversoft.com/claims/is_admin", true);

    Signer signer = new HmacSigner(Algorithm.HS256, "secret");
    Verifier verifier = new HmacVerifier("secret");

    String encodedJwt = JWT.getEncoder().encode(expectedJwt, signer);
    JWT actualJwt = JWT.getDecoder().decode(encodedJwt, verifier);

    assertEquals(actualJwt.audience, expectedJwt.audience);
    assertEquals(actualJwt.expiration, expectedJwt.expiration);
    assertEquals(actualJwt.issuedAt, expectedJwt.issuedAt);
    assertEquals(actualJwt.issuer, expectedJwt.issuer);
    assertEquals(actualJwt.subject, expectedJwt.subject);
    assertEquals(actualJwt.getString("foo"), expectedJwt.getString("foo"));
    assertEquals(actualJwt.getObject("bar"), expectedJwt.getObject("bar"));
    assertEquals(actualJwt.getBoolean("www.inversoft.com/claims/is_admin"), expectedJwt.getBoolean("www.inversoft.com/claims/is_admin"));
  }

  @Test
  public void test_none() throws Exception {
    JWT jwt = new JWT().with(t -> t.subject = "123456789");
    Signer signer = new UnsecuredSigner();

    assertEquals(JWT.getEncoder().encode(jwt, signer), "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkifQ.");
  }

  @Test
  public void test_zonedDateTime() throws Exception {
    ZonedDateTime expiration = ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(60).truncatedTo(ChronoUnit.SECONDS);
    JWT expectedJwt = new JWT().with(t -> t.expiration = expiration);

    Signer signer = new HmacSigner(Algorithm.HS256, "secret");
    Verifier verifier = new HmacVerifier("secret");

    String encodedJwt1 = JWT.getEncoder().encode(expectedJwt, signer);
    JWT actualJwt1 = JWT.getDecoder().decode(encodedJwt1, verifier);

    assertEquals(actualJwt1.expiration, expectedJwt.expiration);
  }
}
