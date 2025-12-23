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

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;

import static org.testng.Assert.assertEquals;

/**
 * @author Daniel DeGroff
 */
public class JSONWebKeySetHelperTest {
  @Test(enabled = false)
  public void test() throws Exception {
    // Retrieve keys using the issuer, well known openid-configuration endpoint and well known JWKS endpoint, all should be equal.

    // Provide the URL to the issuer
    List<JSONWebKey> keys1 = JSONWebKeySetHelper.retrieveKeysFromIssuer("https://accounts.google.com");
    List<JSONWebKey> keys1_useConsumer = JSONWebKeySetHelper.retrieveKeysFromIssuer("https://accounts.google.com", connection -> connection.setConnectTimeout(1_000));

    // Provide the URL to the issuer w/ a trailing slash.
    List<JSONWebKey> keys2 = JSONWebKeySetHelper.retrieveKeysFromIssuer("https://accounts.google.com/"); // Handle trailing slash
    List<JSONWebKey> keys2_useConsumer = JSONWebKeySetHelper.retrieveKeysFromIssuer("https://accounts.google.com/", connection -> connection.setConnectTimeout(1_000));

    // Provide the direct URL to the well-known OIDC discovery document that will contain a URL to the JWKS endpoint
    List<JSONWebKey> keys3 = JSONWebKeySetHelper.retrieveKeysFromWellKnownConfiguration("https://accounts.google.com/.well-known/openid-configuration");
    List<JSONWebKey> keys3_consumer = JSONWebKeySetHelper.retrieveKeysFromWellKnownConfiguration("https://accounts.google.com/.well-known/openid-configuration", connection -> connection.setConnectTimeout(1_000));

    // Provide a URL connection to the well-known OIDC discovery document that will contain a URL to the JWKS endpoint
    List<JSONWebKey> keys4 = JSONWebKeySetHelper.retrieveKeysFromWellKnownConfiguration((HttpURLConnection) new URL("https://accounts.google.com/.well-known/openid-configuration").openConnection());

    // Provide the URL to the JWKS endpoint
    List<JSONWebKey> keys5 = JSONWebKeySetHelper.retrieveKeysFromJWKS("https://www.googleapis.com/oauth2/v3/certs");
    List<JSONWebKey> keys5_consumer = JSONWebKeySetHelper.retrieveKeysFromJWKS("https://www.googleapis.com/oauth2/v3/certs", connection -> connection.setConnectTimeout(1_000));

    // Provide a URL connection to the JWKS endpoint
    List<JSONWebKey> keys6 = JSONWebKeySetHelper.retrieveKeysFromJWKS((HttpURLConnection) new URL("https://www.googleapis.com/oauth2/v3/certs").openConnection());

    assertEquals(keys1, keys1_useConsumer);
    assertEquals(keys1, keys2);

    assertEquals(keys2, keys2_useConsumer);
    assertEquals(keys2, keys3);

    assertEquals(keys3, keys3_consumer);
    assertEquals(keys3, keys4);

    assertEquals(keys4, keys5);

    assertEquals(keys5, keys5_consumer);
    assertEquals(keys5, keys6);
  }
}
