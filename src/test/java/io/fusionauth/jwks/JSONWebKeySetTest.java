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

package io.fusionauth.jwks;

import io.fusionauth.jwks.domain.JSONWebKey;
import org.testng.annotations.Test;

import java.util.List;

import static org.testng.Assert.assertEquals;

/**
 * @author Daniel DeGroff
 */
public class JSONWebKeySetTest {
  @Test
  public void test() {
    // Retrieve keys using the issuer, well known openid-configuration endpoint and well known JWKS endpoint, all should be equal.
    List<JSONWebKey> keys1 = JSONWebKeySetHelper.retrieveKeysFromIssuer("https://accounts.google.com");
    List<JSONWebKey> keys2 = JSONWebKeySetHelper.retrieveKeysFromWellKnownConfiguration("https://accounts.google.com/.well-known/openid-configuration");
    List<JSONWebKey> keys3 = JSONWebKeySetHelper.retrieveKeysFromJWKS("https://www.googleapis.com/oauth2/v3/certs");
    assertEquals(keys1, keys2);
    assertEquals(keys2, keys3);
  }
}
