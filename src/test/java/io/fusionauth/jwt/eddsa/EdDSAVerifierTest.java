/*
 * Copyright (c) 2022, FusionAuth, All Rights Reserved
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

package io.fusionauth.jwt.eddsa;

import io.fusionauth.jwt.BaseJWTTest;
import io.fusionauth.jwt.Verifier;
import io.fusionauth.jwt.domain.Algorithm;
import org.testng.annotations.Test;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * @author Daniel DeGroff
 */
public class EdDSAVerifierTest extends BaseJWTTest {
  @Test
  public void canVerify() {
    Verifier verifier = EdDSAVerifier.newVerifier(getPath("ed_dsa_public_key.pem"));

    assertTrue(verifier.canVerify(Algorithm.EdDSA));

    assertFalse(verifier.canVerify(Algorithm.ES256));
    assertFalse(verifier.canVerify(Algorithm.ES384));
    assertFalse(verifier.canVerify(Algorithm.ES512));

    assertFalse(verifier.canVerify(Algorithm.HS256));
    assertFalse(verifier.canVerify(Algorithm.HS384));
    assertFalse(verifier.canVerify(Algorithm.HS512));

    assertFalse(verifier.canVerify(Algorithm.PS256));
    assertFalse(verifier.canVerify(Algorithm.PS384));
    assertFalse(verifier.canVerify(Algorithm.PS512));

    assertFalse(verifier.canVerify(Algorithm.RS256));
    assertFalse(verifier.canVerify(Algorithm.RS384));
    assertFalse(verifier.canVerify(Algorithm.RS512));
  }
}
