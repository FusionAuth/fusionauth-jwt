/*
 * Copyright (c) 2018-2025, FusionAuth, All Rights Reserved
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
import io.fusionauth.jwt.BaseJWTTest;
import io.fusionauth.jwt.JWTUtils;
import io.fusionauth.jwt.domain.Algorithm;
import io.fusionauth.jwt.domain.KeyPair;
import io.fusionauth.jwt.domain.KeyType;
import io.fusionauth.jwt.json.Mapper;
import io.fusionauth.pem.domain.PEM;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

import static io.fusionauth.jwks.JWKUtils.base64DecodeUint;
import static io.fusionauth.jwks.JWKUtils.base64EncodeUint;
import static io.fusionauth.jwt.domain.Algorithm.RS256;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.fail;

/**
 * Note that the higher invocationCount parameters are helpful to indentify incorrect assumptions in key parsing.
 * <p>
 * Key lengths can differ, and when encoding larger integers in DER encode sequences, or parsing them in and out of
 * JWK formats, we want to be certain we are not making incorrect assumptions. During development, you may wish to
 * run some of these with 5-10k invocation counts to ensure these types of anomalies are un-covered and addressed.
 * <p>
 * It may be reasonable to reduce the invocation counts if tests take too long to run - once we know that the tests
 * will pass with a high number of invocations. However, the time is not yet that significant, and there is value to
 * ensuring that the same result can be expected regardless of the number of times we run the same test.
 *
 * @author Daniel DeGroff
 */
public class JSONWebKeyParserTest extends BaseJWTTest {
  @DataProvider(name = "rsaPublicKeys")
  public Object[][] rsaPublicKeys() {
    return new Object[][]{
        // Apple : https://appleid.apple.com/auth/keys
        {"AQAB", "iGaLqP6y-SJCCBq5Hv6pGDbG_SQ11MNjH7rWHcCFYz4hGwHC4lcSurTlV8u3avoVNM8jXevG1Iu1SY11qInqUvjJur--hghr1b56OPJu6H1iKulSxGjEIyDP6c5BdE1uwprYyr4IO9th8fOwCPygjLFrh44XEGbDIFeImwvBAGOhmMB2AD1n1KviyNsH0bEB7phQtiLk-ILjv1bORSRl8AK677-1T8isGfHKXGZ_ZGtStDe7Lu0Ihp8zoUt59kx2o9uWpROkzF56ypresiIl4WprClRCjz8x6cPZXU2qNWhu71TQvUFwvIvbkE1oYaJMb0jcOTmBRZA2QuYw-zHLwQ"},
        // Google : https://www.googleapis.com/oauth2/v3/certs
        {"AQAB", "q9WQ8_ucw5sLCKMZpWj1WhZXW1C83G6aE7NST1D3cUNnKIN3RhI04EOtJrbfF5wJwmdMurqwIJuhXBC44pyhBkaxJ0-lyrvgLHVhQhxH6K9b-UV0whE0eqiOOl1snKk-N0BRfT5dmCghr7rxcHUJqSFuDpZo2ZJzMiuF2DmeQHaTtusLnU-7xnP4B4eHG_h4nisK1zx8-l-rBYyaGHRf6ZqelTpRDHDVQMGuunbGqVXRgc1OjwPci6ZDzdSFRGST3gCZFirRfOoXMqF2474TD3KjYPdmwfETiPAfOVCA9I2mVj4IhbELDTVVYdh0DBs3mks1j2TBIUniUiDs5c-_ow"},
        // Microsoft : https://login.microsoftonline.com/common/discovery/v2.0/keys
        {"AQAB", "18uZ3P3IgOySlnOsxeIN5WUKzvlm6evPDMFbmXPtTF0GMe7tD2JPfai2UGn74s7AFwqxWO5DQZRu6VfQUux8uMR4J7nxm1Kf__7pVEVJJyDuL5a8PARRYQtH68w-0IZxcFOkgsSdhtIzPQ2jj4mmRzWXIwh8M_8pJ6qiOjvjF9bhEq0CC_f27BnljPaFn8hxY69pCoxenWWqFcsUhFZvCMthhRubAbBilDr74KaXS5xCgySBhPzwekD9_NdCUuCsdqavd4T-VWnbplbB8YsC-R00FptBFKuTyT9zoGZjWZilQVmj7v3k8jXqYB2nWKgTAfwjmiyKz78FHkaE-nCIDw"}
    };
  }

  @DataProvider(name = "ecPublicKeys")
  public Object[][] ecPublicKeys() {
    // X and Y coordinates from EC JSON Web Keys
    return new Object[][]{/*
        Alg     Crv      X, Y
        --------------------------------------------------------------------------------------------------------------*/
        {"P-256", "NIWpsIea0qzB22S0utDG8dGFYqEInv9C7ZgZuKtwjno", "iVFFtTgiInz_fjh-n1YqbibnUb2vtBZFs3wPpQw3mc0"},
        {"P-384", "z6kxnA_HZP8t9F9XBH-YYggdQi4FrcuhSElu0mxcRITIuJG7YgtSWYUmBHNv9J0-", "uDShjOHRepB5ll8B8Cs-A4kxbs8cl-PfE0gAtqE72Cdhbb5ZPNclrzi6rSfx1TuU"},
        {"P-521", "AASKtNZn-wSH5gPokx0SR2R9rpv8Gzf8pmSUJ8dBvrsSLSL-nSMtQC5lsmgTKpyd8p3WZFkn3BkUgYPrNxrR8Wcy", "AehbMYfcRK8RfeHG2XHyWM0PuEVWcKB35NwXhce9meNyjsgJAZPBaCfR9FqDZrPCc4ARpw9UNmlYsZ-j3wHmxu-M"}
    };
  }

  @Test
  public void parse_ec_certificates() throws Exception {
    // Just parsing, expecting no explosions.

    // EC 256 Certificate
    byte[] certificate256 = Files.readAllBytes(Paths.get("src/test/resources/jwk/ec_certificate_p_256.json"));
    JSONWebKey.parse(Mapper.deserialize(certificate256, JSONWebKey.class));

    // EC 384 Certificate
    byte[] certificate384 = Files.readAllBytes(Paths.get("src/test/resources/jwk/ec_certificate_p_384.json"));
    JSONWebKey.parse(Mapper.deserialize(certificate384, JSONWebKey.class));

    // EC 521 Certificate
    byte[] certificate521 = Files.readAllBytes(Paths.get("src/test/resources/jwk/ec_certificate_p_521.json"));
    JSONWebKey.parse(Mapper.deserialize(certificate521, JSONWebKey.class));

    // Hacked public key
    byte[] hacked256 = Files.readAllBytes(Paths.get("src/test/resources/jwk/ec_certificate_hacked_x5c_p_256.json"));
    try {
      JSONWebKey.parse(Mapper.deserialize(hacked256, JSONWebKey.class));
      fail("Expected an exception");
    } catch (JSONWebKeyParserException expected) {
      assertEquals(expected.getMessage(),
          "Expected an x coordinate value of [92281275340165409471170845681463968816032370456437802964396339248939820362156] but found [114355049275855008944383887078211226358178801567209304915100916863237914171390].  The certificate found in [x5c] does not match the [x] coordinate property.");
    }
  }

  @Test
  public void parse_rsa_certificates() throws Exception {
    // Just parsing, expecting no explosions.

    // RSA 2048 bit Certificate
    byte[] certificate256 = Files.readAllBytes(Paths.get("src/test/resources/jwk/rsa_certificate_2048.json"));
    JSONWebKey.parse(Mapper.deserialize(certificate256, JSONWebKey.class));

    // Hacked public key
    byte[] hacked256 = Files.readAllBytes(Paths.get("src/test/resources/jwk/rsa_certificate_hacked_x5c_2048.json"));
    try {
      JSONWebKey.parse(Mapper.deserialize(hacked256, JSONWebKey.class));
      fail("Expected an exception");
    } catch (JSONWebKeyParserException expected) {
      assertEquals(expected.getMessage(),
          "Expected a modulus value of [23801198360346180032294480920715767764472197020631570074480649915781538912816195975417363780765112968383673580578571989252090383113994304028563474394397459725649506248716739361908616836476913309708506822850917404774975668734124236432466647775976571217892167355716913557523437407297392112679627645666491794339857374054870860501484016751889383673483750306612278874647610454856410468740384624100471457481543991766630885386515400127553119191608234405247675208060619388776358270769904028886336830442777210583872889885286842313649680068015006466942721801737282566078347249842971299237584314259050491201295146063321006623569] but found [23464936089672074238558227240738642188401652750559322139110223472800898724452171193507830144175059459702529905676615071074993228771373136540482674196545025295733738196449583666610315977490986925474739841268554665863093665527055011951462798054655387514678326260004075182975117421140397782473200702068600919372009187240660911098390145147467211797777009862056159391483377819086435980778585967055870497149033762110952962582355410428105094882392320868563187123866160347835848217107617930191075074037337201254401445272297107644739005851884807909929228393436982535239808806968215135043030563617161016982313909247836020691707].  The certificate found in [x5c] does not match the [n] property.");
    }
  }

  @Test(dataProvider = "ecPublicKeys")
  public void parse_ec_keys(String curve, String x, String y) {
    JSONWebKey expected = new JSONWebKey();
    expected.crv = curve;
    expected.kty = KeyType.EC;
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
  public void parse_well_known(String exponent, String modulus) {
    JSONWebKey expected = new JSONWebKey();
    expected.kty = KeyType.RSA;
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

  @Test(invocationCount = 1_000)
  public void parse_ec() {
    KeyPair keyPair = JWTUtils.generate256_ECKeyPair();

    // Build a JSON Web Key from our own EC key pair
    JSONWebKey expected = JSONWebKey.build(keyPair.publicKey);
    expected.alg = Algorithm.ES256;

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

  @DataProvider(name = "EdDSA")
  public Object[][] edDSA() {
    return new Object[][]{
        {"Ed25519"},
        {"Ed448"},
    };
  }

  @Test(dataProvider = "EdDSA", invocationCount = 1_000)
  public void parse_eddsa(String curve) {
    KeyPair keyPair = curve.equals("Ed25519")
        ? JWTUtils.generate_ed25519_EdDSAKeyPair()
        : JWTUtils.generate_ed448_EdDSAKeyPair();

    // Build a JSON Web Key from our own EdDSA key pair
    JSONWebKey expected = JSONWebKey.build(keyPair.publicKey);
    expected.alg = Algorithm.Ed25519;

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

  @Test(invocationCount = 1_000)
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
