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

import org.primeframework.jwt.domain.JWT;
import org.primeframework.jwt.hmac.HMACVerifier;
import org.primeframework.jwt.rsa.RSAVerifier;
import org.testng.annotations.Test;
import org.testng.internal.collections.Pair;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.fail;

/**
 * @author Daniel DeGroff
 */
public class VerifierTest {

  static List<Pair<Verifier, String>> algorithms = new ArrayList<>();

  @Test
  public void verify() throws Exception {

    // JWT Subject : 123456789
    for (Pair<Verifier, String> algorithm : algorithms) {

      // Implicit call to verifier.verify and get a JWT back
      try {
        JWT jwt = JWT.getDecoder().decode(algorithm.second(), algorithm.first());
        assertNotNull(jwt);
        assertEquals(jwt.subject, "123456789");
      } catch (Exception e) {
        fail("Failed to validate signature.", e);
      }
    }
  }

  static {
    try {
      algorithms.add(new Pair<>(HMACVerifier.newVerifier("secret"), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.qHdut1UR4-2FSAvh7U3YdeRR5r5boVqjIGQ16Ztp894"));
      algorithms.add(new Pair<>(RSAVerifier.newVerifier(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_public_key_4096.pem")))),
          "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.kRXJkOHC98D0LCT2oPg5fTmQJDFXkMRQJopbt7QM6prmQDHwjJL_xO-_EXRXnbvf5NLORto45By3XNn2ZzWmY3pAOxj46MlQ5elhROx2S-EnHZNLfQhoG8ZXPZ54q-Obz_6K7ZSlkAQ8jmeZUO3Ryi8jRlHQ2PT4LbBtLpaf982SGJfeTyUMw1LbvowZUTZSF-E6JARaokmmx8M2GeLuKcFhU-YsBTXUarKp0IJCy3jpMQ2zW_HGjyVWH8WwSIbSdpBn7ztoQEJYO-R5H3qVaAz2BsTuGLRxoyIu1iy2-QcDp5uTufmX1roXM8ciQMpcfwKGiyNpKVIZm-lF8aROXRL4kk4rqp6KUzJuOPljPXRU--xKSua-DeR0BEerKzI9hbwIMWiblCslAciNminoSc9G7pUyVwV5Z5IT8CGJkVgoyVGELeBmYCDy7LHwXrr0poc0hPbE3mJXhzolga4BB84nCg2Hb9tCNiHU8F-rKgZWCONaSSIdhQ49x8OiPafFh2DJBEBe5Xbm6xdCfh3KVG0qe4XL18R5s98aIP9UIC4i62UEgPy6W7Fr7QgUxpXrjRCERBV3MiNu4L8NNJb3oZleq5lQi72EfdS-Bt8ZUOVInIcAvSmu-3i8jB_2sF38XUXdl8gkW8k_b9dJkzDcivCFehvSqGmm3vBm5X4bNmk"));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }
}
