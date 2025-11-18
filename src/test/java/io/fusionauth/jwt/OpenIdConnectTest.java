/*
 * Copyright (c) 2016-2025, FusionAuth, All Rights Reserved
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

import io.fusionauth.jwt.domain.Algorithm;
import org.testng.annotations.Test;

import static io.fusionauth.jwt.OpenIDConnect.at_hash;
import static io.fusionauth.jwt.OpenIDConnect.c_hash;
import static org.testng.Assert.assertEquals;
import static org.testng.AssertJUnit.fail;

/**
 * @author Daniel DeGroff
 */
public class OpenIdConnectTest {
  @Test
  public void test_at_hash() {
    assertEquals(at_hash("dNZX1hEZ9wBCzNL40Upu646bdzQA", Algorithm.HS256), "wfgvmE9VxjAudsl9lc6TqA");
    assertEquals(at_hash("dNZX1hEZ9wBCzNL40Upu646bdzQA", Algorithm.HS384), "phZaPQJosyg-qi-OIYyQ3xJB9wsHYEEz");
    assertEquals(at_hash("dNZX1hEZ9wBCzNL40Upu646bdzQA", Algorithm.HS512), "8xltSlOGYrWy8W9yNvRlEth1i_bXW-JROWPLvCv5zog");

    assertEquals(at_hash("dNZX1hEZ9wBCzNL40Upu646bdzQA", Algorithm.ES256), "wfgvmE9VxjAudsl9lc6TqA");
    assertEquals(at_hash("dNZX1hEZ9wBCzNL40Upu646bdzQA", Algorithm.ES384), "phZaPQJosyg-qi-OIYyQ3xJB9wsHYEEz");
    assertEquals(at_hash("dNZX1hEZ9wBCzNL40Upu646bdzQA", Algorithm.ES512), "8xltSlOGYrWy8W9yNvRlEth1i_bXW-JROWPLvCv5zog");

    assertEquals(at_hash("dNZX1hEZ9wBCzNL40Upu646bdzQA", Algorithm.RS256), "wfgvmE9VxjAudsl9lc6TqA");
    assertEquals(at_hash("dNZX1hEZ9wBCzNL40Upu646bdzQA", Algorithm.RS384), "phZaPQJosyg-qi-OIYyQ3xJB9wsHYEEz");
    assertEquals(at_hash("dNZX1hEZ9wBCzNL40Upu646bdzQA", Algorithm.RS512), "8xltSlOGYrWy8W9yNvRlEth1i_bXW-JROWPLvCv5zog");

    // Note that we are not able to differentiate between ed25519 and ed448
    // - https://bitbucket.org/openid/connect/issues/1125/_hash-algorithm-for-eddsa-id-tokens
    assertEquals(at_hash("dNZX1hEZ9wBCzNL40Upu646bdzQA", Algorithm.EdDSA), "8xltSlOGYrWy8W9yNvRlEth1i_bXW-JROWPLvCv5zog");

    // Controls
    assertEquals(at_hash("1940a308-d492-3660-a9f8-46723cc582e9", Algorithm.RS256), "JrZY9MtYVEIIJUx-DDBmww");
    assertEquals(at_hash("jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y", Algorithm.RS256), "77QmUPtjPfzWtF2AnpK9RQ");
  }

  @Test
  public void test_c_hash() {
    assertEquals(c_hash("dNZX1hEZ9wBCzNL40Upu646bdzQA", Algorithm.HS256), "wfgvmE9VxjAudsl9lc6TqA");
    assertEquals(c_hash("dNZX1hEZ9wBCzNL40Upu646bdzQA", Algorithm.HS384), "phZaPQJosyg-qi-OIYyQ3xJB9wsHYEEz");
    assertEquals(c_hash("dNZX1hEZ9wBCzNL40Upu646bdzQA", Algorithm.HS512), "8xltSlOGYrWy8W9yNvRlEth1i_bXW-JROWPLvCv5zog");

    assertEquals(c_hash("dNZX1hEZ9wBCzNL40Upu646bdzQA", Algorithm.ES256), "wfgvmE9VxjAudsl9lc6TqA");
    assertEquals(c_hash("dNZX1hEZ9wBCzNL40Upu646bdzQA", Algorithm.ES384), "phZaPQJosyg-qi-OIYyQ3xJB9wsHYEEz");
    assertEquals(c_hash("dNZX1hEZ9wBCzNL40Upu646bdzQA", Algorithm.ES512), "8xltSlOGYrWy8W9yNvRlEth1i_bXW-JROWPLvCv5zog");

    assertEquals(c_hash("dNZX1hEZ9wBCzNL40Upu646bdzQA", Algorithm.RS256), "wfgvmE9VxjAudsl9lc6TqA");
    assertEquals(c_hash("dNZX1hEZ9wBCzNL40Upu646bdzQA", Algorithm.RS384), "phZaPQJosyg-qi-OIYyQ3xJB9wsHYEEz");
    assertEquals(c_hash("dNZX1hEZ9wBCzNL40Upu646bdzQA", Algorithm.RS512), "8xltSlOGYrWy8W9yNvRlEth1i_bXW-JROWPLvCv5zog");

    // Note that we are not able to differentiate between ed25519 and ed448
    // - https://bitbucket.org/openid/connect/issues/1125/_hash-algorithm-for-eddsa-id-tokens
    assertEquals(c_hash("dNZX1hEZ9wBCzNL40Upu646bdzQA", Algorithm.EdDSA), "8xltSlOGYrWy8W9yNvRlEth1i_bXW-JROWPLvCv5zog");

    // Controls
    assertEquals(c_hash("16fd899f-5f0c-3114-875e-2547b629cd05", Algorithm.HS256), "S5UOXRNNyYsI6Z0G3xxdpw");
    assertEquals(c_hash("Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk", Algorithm.HS256), "LDktKdoQak3Pk0cnXxCltA");
  }

  @Test
  public void validation() {
    try {
      OpenIDConnect.at_hash("foo", Algorithm.none);
      fail("expected exception when passing an invalid Algorithm");
    } catch (IllegalArgumentException ignore) {
    }

    try {
      c_hash("foo", Algorithm.none);
      fail("expected exception when passing an invalid Algorithm");
    } catch (IllegalArgumentException ignore) {
    }
  }
}
