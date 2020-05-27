/*
 * Copyright (c) 2018-2019, FusionAuth, All Rights Reserved
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
import io.fusionauth.jwt.BaseTest;
import io.fusionauth.jwt.JWTUtils;
import io.fusionauth.jwt.domain.Algorithm;
import io.fusionauth.jwt.domain.KeyPair;
import io.fusionauth.pem.domain.PEM;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

import static io.fusionauth.jwks.JWKUtils.base64DecodeUint;
import static io.fusionauth.jwks.JWKUtils.base64EncodeUint;
import static io.fusionauth.jwt.domain.Algorithm.ES256;
import static io.fusionauth.jwt.domain.Algorithm.ES384;
import static io.fusionauth.jwt.domain.Algorithm.ES512;
import static io.fusionauth.jwt.domain.Algorithm.RS256;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

/**
 * @author Daniel DeGroff
 */
public class JSONWebKeyParserTest extends BaseTest {
  @DataProvider(name = "rsaPublicKeys")
  public Object[][] rsaPublicKeys() {
    return new Object[][]{
        // Apple : https://appleid.apple.com/auth/keys
        {RS256, "AQAB", "iGaLqP6y-SJCCBq5Hv6pGDbG_SQ11MNjH7rWHcCFYz4hGwHC4lcSurTlV8u3avoVNM8jXevG1Iu1SY11qInqUvjJur--hghr1b56OPJu6H1iKulSxGjEIyDP6c5BdE1uwprYyr4IO9th8fOwCPygjLFrh44XEGbDIFeImwvBAGOhmMB2AD1n1KviyNsH0bEB7phQtiLk-ILjv1bORSRl8AK677-1T8isGfHKXGZ_ZGtStDe7Lu0Ihp8zoUt59kx2o9uWpROkzF56ypresiIl4WprClRCjz8x6cPZXU2qNWhu71TQvUFwvIvbkE1oYaJMb0jcOTmBRZA2QuYw-zHLwQ"},
        // Google : https://www.googleapis.com/oauth2/v3/certs
        {RS256, "AQAB", "q9WQ8_ucw5sLCKMZpWj1WhZXW1C83G6aE7NST1D3cUNnKIN3RhI04EOtJrbfF5wJwmdMurqwIJuhXBC44pyhBkaxJ0-lyrvgLHVhQhxH6K9b-UV0whE0eqiOOl1snKk-N0BRfT5dmCghr7rxcHUJqSFuDpZo2ZJzMiuF2DmeQHaTtusLnU-7xnP4B4eHG_h4nisK1zx8-l-rBYyaGHRf6ZqelTpRDHDVQMGuunbGqVXRgc1OjwPci6ZDzdSFRGST3gCZFirRfOoXMqF2474TD3KjYPdmwfETiPAfOVCA9I2mVj4IhbELDTVVYdh0DBs3mks1j2TBIUniUiDs5c-_ow"},
        // Microsoft : https://login.microsoftonline.com/common/discovery/v2.0/keys
        {RS256, "AQAB", "18uZ3P3IgOySlnOsxeIN5WUKzvlm6evPDMFbmXPtTF0GMe7tD2JPfai2UGn74s7AFwqxWO5DQZRu6VfQUux8uMR4J7nxm1Kf__7pVEVJJyDuL5a8PARRYQtH68w-0IZxcFOkgsSdhtIzPQ2jj4mmRzWXIwh8M_8pJ6qiOjvjF9bhEq0CC_f27BnljPaFn8hxY69pCoxenWWqFcsUhFZvCMthhRubAbBilDr74KaXS5xCgySBhPzwekD9_NdCUuCsdqavd4T-VWnbplbB8YsC-R00FptBFKuTyT9zoGZjWZilQVmj7v3k8jXqYB2nWKgTAfwjmiyKz78FHkaE-nCIDw"}
    };
  }

  @DataProvider(name = "ecPublicKeys")
  public Object[][] ecPublicKeys() {
    // X and Y coordinates from EC JSON Web Keys
    return new Object[][]{/*
        Alg     Crv      X, Y
        --------------------------------------------------------------------------------------------------------------*/
        {ES256, "P-256", "NIWpsIea0qzB22S0utDG8dGFYqEInv9C7ZgZuKtwjno", "iVFFtTgiInz_fjh-n1YqbibnUb2vtBZFs3wPpQw3mc0"},
        {ES384, "P-384", "z6kxnA_HZP8t9F9XBH-YYggdQi4FrcuhSElu0mxcRITIuJG7YgtSWYUmBHNv9J0-", "uDShjOHRepB5ll8B8Cs-A4kxbs8cl-PfE0gAtqE72Cdhbb5ZPNclrzi6rSfx1TuU"},
        {ES512, "P-521", "AASKtNZn-wSH5gPokx0SR2R9rpv8Gzf8pmSUJ8dBvrsSLSL-nSMtQC5lsmgTKpyd8p3WZFkn3BkUgYPrNxrR8Wcy", "AehbMYfcRK8RfeHG2XHyWM0PuEVWcKB35NwXhce9meNyjsgJAZPBaCfR9FqDZrPCc4ARpw9UNmlYsZ-j3wHmxu-M"}
    };
  }

  @Test(dataProvider = "ecPublicKeys")
  public void parse_ec_keys(Algorithm algorithm, String curve, String x, String y) {
    JSONWebKey expected = new JSONWebKey();
    expected.alg = algorithm;
    expected.crv = curve;
    expected.x = x;
    expected.y = y;

    PublicKey publicKey = JSONWebKey.parse(expected);
    assertNotNull(publicKey);

    // Compare to the original expected key
    String encodedPEM = PEM.encode(publicKey);
    assertEquals(JSONWebKey.build(encodedPEM).x, expected.x);
    assertEquals(JSONWebKey.build(encodedPEM).y, expected.y);

    // Get the public key from the PEM, and assert against the expected values
    PEM pem = PEM.decode(encodedPEM);
    assertEquals(JSONWebKey.build(pem.publicKey).x, expected.x);
    assertEquals(JSONWebKey.build(pem.publicKey).y, expected.y);
  }


  @Test(dataProvider = "rsaPublicKeys")
  public void parse_well_known(Algorithm algorithm, String exponent, String modulus) {
    JSONWebKey expected = new JSONWebKey();
    expected.alg = algorithm;
    expected.e = exponent;
    expected.n = modulus;

    PublicKey publicKey = JSONWebKey.parse(expected);
    assertNotNull(publicKey);

    // Compare to the original expected key
    String encodedPEM = PEM.encode(publicKey);
    assertEquals(JSONWebKey.build(encodedPEM).n, expected.n);
    assertEquals(JSONWebKey.build(encodedPEM).e, expected.e);

    // Get the public key from the PEM, and assert against the expected values
    PEM pem = PEM.decode(encodedPEM);
    assertEquals(JSONWebKey.build(pem.publicKey).n, expected.n);
    assertEquals(JSONWebKey.build(pem.publicKey).e, expected.e);
  }

  @Test
  public void unsignedEncodingTest() {
    // Generate a key pair and produce the RSA Public key as well as the PEM
    KeyPair keyPair = JWTUtils.generate2048_RSAKeyPair();
    PEM pem = PEM.decode(keyPair.publicKey);
    JSONWebKey key = JSONWebKey.build(keyPair.publicKey);

    // Collect the Modulus and Exponent from the public key produced by the PEM
    BigInteger controlN = ((RSAPublicKey) pem.publicKey).getModulus();
    BigInteger controlE = ((RSAPublicKey) pem.publicKey).getPublicExponent();

    // Now decode, and then re-encode the modulus to ensure we can go round trip and not mess it up.
    BigInteger bigIntegerN = base64DecodeUint(key.n);
    String encodedN = base64EncodeUint(bigIntegerN);

    assertEquals(controlN, bigIntegerN);
    assertEquals(key.n, encodedN);

    // Now decode, and then re-encode the exponent to ensure we can go round trip and not mess it up.
    BigInteger bigIntegerE = base64DecodeUint(key.e);
    String encodedE = base64EncodeUint(bigIntegerE);

    assertEquals(controlE, bigIntegerE);
    assertEquals(key.e, encodedE);
  }

  @Test
  public void parse_rsa() {
    KeyPair keyPair = JWTUtils.generate2048_RSAKeyPair();

    // Build a JSON Web Key from our own RSA key pair
    JSONWebKey expected = JSONWebKey.build(keyPair.publicKey);
    expected.alg = RS256;

    PublicKey publicKey = JSONWebKey.parse(expected);
    assertNotNull(publicKey);

    // Compare to the original expected key
    String encodedPEM = PEM.encode(publicKey);
    assertEquals(JSONWebKey.build(encodedPEM).n, expected.n);
    assertEquals(JSONWebKey.build(encodedPEM).e, expected.e);

    // Get the public key from the PEM, and assert against the expected values
    PEM pem = PEM.decode(encodedPEM);
    assertEquals(JSONWebKey.build(pem.publicKey).n, expected.n);
    assertEquals(JSONWebKey.build(pem.publicKey).e, expected.e);
  }
}
