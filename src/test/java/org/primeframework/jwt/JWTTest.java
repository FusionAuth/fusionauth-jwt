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
import org.testng.annotations.Test;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

import static org.testng.Assert.assertEquals;

/**
 * @author Daniel DeGroff
 */
public class JWTTest {

  @Test(enabled = false)
  public void performance() throws Exception {
    // Re-use the signer
    Signer hmacSigner = new HmacSigner(Algorithm.HS256).withSecret("secret");
    Signer rsaSigner = new RSASigner(Algorithm.RS256)
        .withPrivateKey(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_private_key_4096"))))
        .withPublicKey(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_public_key_4096"))));

    long iterationCount = 1_000;
    for (Signer signer : Arrays.asList(hmacSigner, rsaSigner)) {
      long now = System.currentTimeMillis();
      // 500,000 Iterations
      for (int i = 0; i < iterationCount; i++) {
        new JWT()
            .withSigner(signer)
            .subject("123456789")
            .get();
      }
      long duration = System.currentTimeMillis() - now;
      System.out.println("[" + signer.algorithm.algorithmName + "] " + duration + " milliseconds total. [" + iterationCount + "] iterations.");
    }
  }

  @Test
  public void test_HS256() throws Exception {
    String jwt = new JWT()
        .withSigner(new HmacSigner(Algorithm.HS256).withSecret("secret"))
        .subject("123456789")
        .get();

    assertEquals(jwt, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.qHdut1UR4-2FSAvh7U3YdeRR5r5boVqjIGQ16Ztp894");
  }

  @Test
  public void test_HS512() throws Exception {
    String jwt = new JWT()
        .withSigner(new HmacSigner(Algorithm.HS512).withSecret("secret"))
        .subject("123456789")
        .get();

    assertEquals(jwt, "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.MgAi9gfGkep-IoFYPHMhHz6w2Kxf0u8TZ-wNeQOLPwc8emLNKOMqBU-5dJXeaY5-8wQ1CvZycWHbEilvHgN6Ug");
  }

  @Test
  public void test_RS256() throws Exception {
    RSASigner signer = new RSASigner(Algorithm.RS256)
        .withPrivateKey(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_private_key_4096"))));

    String jwt = new JWT()
        .withSigner(signer)
        .subject("123456789").get();

    assertEquals(jwt, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.kRXJkOHC98D0LCT2oPg5fTmQJDFXkMRQJopbt7QM6prmQDHwjJL_xO-_EXRXnbvf5NLORto45By3XNn2ZzWmY3pAOxj46MlQ5elhROx2S-EnHZNLfQhoG8ZXPZ54q-Obz_6K7ZSlkAQ8jmeZUO3Ryi8jRlHQ2PT4LbBtLpaf982SGJfeTyUMw1LbvowZUTZSF-E6JARaokmmx8M2GeLuKcFhU-YsBTXUarKp0IJCy3jpMQ2zW_HGjyVWH8WwSIbSdpBn7ztoQEJYO-R5H3qVaAz2BsTuGLRxoyIu1iy2-QcDp5uTufmX1roXM8ciQMpcfwKGiyNpKVIZm-lF8aROXRL4kk4rqp6KUzJuOPljPXRU--xKSua-DeR0BEerKzI9hbwIMWiblCslAciNminoSc9G7pUyVwV5Z5IT8CGJkVgoyVGELeBmYCDy7LHwXrr0poc0hPbE3mJXhzolga4BB84nCg2Hb9tCNiHU8F-rKgZWCONaSSIdhQ49x8OiPafFh2DJBEBe5Xbm6xdCfh3KVG0qe4XL18R5s98aIP9UIC4i62UEgPy6W7Fr7QgUxpXrjRCERBV3MiNu4L8NNJb3oZleq5lQi72EfdS-Bt8ZUOVInIcAvSmu-3i8jB_2sF38XUXdl8gkW8k_b9dJkzDcivCFehvSqGmm3vBm5X4bNmk");
  }

  @Test
  public void test_RS512() throws Exception {
    String jwt = new JWT()
        .withSigner(new RSASigner(Algorithm.RS512)
            .withPrivateKey(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_private_key_4096")))))
        .subject("123456789").get();

    assertEquals(jwt, "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.ei28WNoJdUpMlLnHr78HiTnnuKwSRLYcOpgUC3daVInT5RAc0kk2Ipx16Z-bHL_eFLSYgF3TSKdymFpNf8cnEu5T6rH0azYSZLrPmVCetDxjo-ixXK9asPOF3JuIbDjN7ow3K-CMbMCWzWp04ZAh-DNecYEd3HiGgooPVGA4HuVXZFHH8XfQ9TD-64ppBQTWgW32vkna8ILKyIXdwWXSEfCZYfLzLZnilJrz820wZJ5JMXimv2au0OwwRobUMLEBUM4iuEPXLf5wFJU6LcU0XMuovavfIXKDpvP9Yfz6UplMlFvIr9y72xExfaNt32vwneAP-Fpg2x9wYvR0W8LhXKZaFRfcYwhbj17GCAbpx34hjiqnwyFStn5Qx_QHz_Y7ck-ZXB2MGUkiYGj9y_8bQNx-LIaTQUX6sONTNdVVCfnOnMHFqVbupGho24K7885-8BxCRojvA0ggneF6dsKCQvAt2rsVRso0TrCVxwYItb9tRsyhCbWou-zh_08JlYGVXPiGY3RRQDfxCc9RHQUflWRS9CBcPtoaco4mFKZSM-9e_xoYx__DEzM3UjaI4jReLM-IARwlVPoHJa2Vcb5wngZTaxGf2ToMq7R_8KecZymb3OaA2X1e8GS2300ySwsXbOz0sJv2a7_JUncSEBPSsb2vMMurxSJ4E3RTAc4s3aU");
  }

  @Test
  public void test_none() throws Exception {
    String jwt = new JWT()
        .withSigner(new UnsecuredSigned())
        .subject("123456789").get();

    assertEquals(jwt, "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkifQ.");
  }
}
