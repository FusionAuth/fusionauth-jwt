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

import org.primeframework.jwt.domain.Algorithm;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.AssertJUnit.fail;

/**
 * @author Daniel DeGroff
 */
public class OpenIdConnectTest {
  @Test
  public void at_hash() throws Exception {
    String encodedAccessToken = "dNZX1hEZ9wBCzNL40Upu646bdzQA";
    String at_hash = OpenIDConnect.at_hash(encodedAccessToken, Algorithm.RS256);
    assertEquals(at_hash, "wfgvmE9VxjAudsl9lc6TqA");

    // Check for supported types using all RSA Algorithms, no exceptions thrown
    OpenIDConnect.at_hash(encodedAccessToken, Algorithm.RS384);
    OpenIDConnect.at_hash(encodedAccessToken, Algorithm.RS512);
  }

  @Test
  public void at_hash_validation() throws Exception {
    try {
      OpenIDConnect.at_hash("foo", Algorithm.HS256);
      fail("expected exception when passing an invalid Algorithm");
    } catch (IllegalArgumentException ignore) {
    }

    try {
      OpenIDConnect.at_hash("foo", Algorithm.HS384);
      fail("expected exception when passing an invalid Algorithm");
    } catch (IllegalArgumentException ignore) {
    }

    try {
      OpenIDConnect.at_hash("foo", Algorithm.HS512);
      fail("expected exception when passing an invalid Algorithm");
    } catch (IllegalArgumentException ignore) {
    }
  }

  @Test
  public void c_hash() throws Exception {
    String authCode = "dNZX1hEZ9wBCzNL40Upu646bdzQA";
    String c_hash = OpenIDConnect.c_hash(authCode, Algorithm.RS256);
    assertEquals(c_hash, "wfgvmE9VxjAudsl9lc6TqJpdYffcmbmtN9wSs3Ix_50");

    // Check for supported types using all RSA Algorithms, no exceptions thrown
    OpenIDConnect.c_hash(authCode, Algorithm.RS384);
    OpenIDConnect.c_hash(authCode, Algorithm.RS512);
  }
}
