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
import io.fusionauth.jwt.Signer;
import io.fusionauth.jwt.Verifier;
import io.fusionauth.jwt.domain.Algorithm;
import io.fusionauth.jwt.domain.Header;
import io.fusionauth.jwt.domain.JWT;
import io.fusionauth.jwt.rsa.RSAPSSSigner;
import io.fusionauth.jwt.rsa.RSAPSSVerifier;
import io.fusionauth.jwt.rsa.RSASigner;
import io.fusionauth.pem.domain.PEM;
import org.testng.annotations.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Map;

import static org.testng.Assert.assertEquals;

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
public class JSONWebKeyBuilderTest extends BaseJWTTest {
  @Test
  public void add_named_properties() {
    Arrays.asList(
        "alg",
        "crv",
        "d",
        "dp",
        "dq",
        "e",
        "kid",
        "kty",
        "n",
        "p",
        "q",
        "qi",
        "use",
        "x",
        "x5c",
        "x5t",
        "x5t_256",
        "y"
    ).forEach(key -> expectException(JSONWebKeyBuilderException.class, () -> new JSONWebKey().add(key, "Nunya, Business")));
  }

  @Test
  public void ec_private() throws Exception {
    // EC 256 Private key - PKCS#8 encapsulated already
    ECPrivateKey key = PEM.decode(Paths.get("src/test/resources/ec_private_prime256v1_p_256_openssl_pkcs8.pem")).getPrivateKey();
    assertJSONEquals(JSONWebKey.build(key), "src/test/resources/jwk/ec_private_prime256v1_p_256_openssl_pkcs8.json");
  }

  @Test
  public void ec_public() throws Exception {
    // EC 256 Public key
    ECPublicKey ecPublic_p256 = PEM.decode(Paths.get("src/test/resources/ec_public_key_p_256.pem")).getPublicKey();
    assertJSONEquals(JSONWebKey.build(ecPublic_p256), "src/test/resources/jwk/ec_public_key_p_256.json");

    // EC 256 Certificate
    Certificate ec_certificate_p256 = PEM.decode(Paths.get("src/test/resources/ec_certificate_p_256.pem")).getCertificate();
    assertJSONEquals(JSONWebKey.build(ec_certificate_p256), "src/test/resources/jwk/ec_certificate_p_256.json");

    // EC 384 Public key
    ECPublicKey ecPublic_p384 = PEM.decode(Paths.get("src/test/resources/ec_public_key_p_384.pem")).getPublicKey();
    assertJSONEquals(JSONWebKey.build(ecPublic_p384), "src/test/resources/jwk/ec_public_key_p_384.json");

    // EC 384 Certificate
    Certificate ec_certificate_p384 = PEM.decode(Paths.get("src/test/resources/ec_certificate_p_384.pem")).getCertificate();
    assertJSONEquals(JSONWebKey.build(ec_certificate_p384), "src/test/resources/jwk/ec_certificate_p_384.json");

    // EC 521 Public key
    ECPublicKey ecPublic_p512 = PEM.decode(Paths.get("src/test/resources/ec_public_key_p_521.pem")).getPublicKey();
    assertJSONEquals(JSONWebKey.build(ecPublic_p512), "src/test/resources/jwk/ec_public_key_p_521.json");

    // EC 521 Certificate
    Certificate ec_certificate_p512 = PEM.decode(Paths.get("src/test/resources/ec_certificate_p_521.pem")).getCertificate();
    assertJSONEquals(JSONWebKey.build(ec_certificate_p512), "src/test/resources/jwk/ec_certificate_p_521.json");

    // EC Reference P-521
    ECPublicKey ec521key = PEM.decode(Paths.get("src/test/resources/ec_public_p_521_reference.pem")).getPublicKey();
    assertJSONEquals(JSONWebKey.build(ec521key), "src/test/resources/jwk/ec_public_p_521_reference.json");
  }

  @Test
  public void extra_properties() throws Exception {
    // EC 256 Public key
    ECPublicKey ecPublic_p256 = PEM.decode(Paths.get("src/test/resources/ec_public_key_p_256.pem")).getPublicKey();
    assertJSONEquals(JSONWebKey.build(ecPublic_p256)
        .add("more", "cowbell")
        .add("boom", "goes the dynamite"), "src/test/resources/jwk/extra_properties.json");
  }

  @Test
  public void rsa_private() throws Exception {
    // RSA private key
    RSAPrivateKey privateKey = PEM.decode(Paths.get("src/test/resources/rsa_private_key_jwk_control.pem")).getPrivateKey();
    assertJSONEquals(JSONWebKey.build(privateKey), "src/test/resources/jwk/rsa_private_key_jwk_control.json");
  }

  @Test
  public void rsa_pss_private() throws Exception {
    // RSA PSS private key
    RSAPrivateKey privateKey = PEM.decode(Paths.get("src/test/resources/rsa_pss_private_key_2048.pem")).getPrivateKey();
    // Note that the alg property in the JWK is optional, and with an RSA key we don't know the algorithm.
    // - This key could be used with PS256, PS384 or PS512.
    assertJSONEquals(JSONWebKey.build(privateKey), "src/test/resources/jwk/rsa_pss_private_key_2048.json");

    // See!
    Signer signer = RSAPSSSigner.newSHA256Signer(privateKey);
    String message = "hello world!";
    byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
    byte[] signature = signer.sign(message);

    RSAPublicKey publicKey = PEM.decode(Paths.get("src/test/resources/rsa_pss_public_key_2048.pem")).getPublicKey();
    Verifier verifier = RSAPSSVerifier.newVerifier(publicKey);
    verifier.canVerify(Algorithm.PS256);
    verifier.canVerify(Algorithm.PS384);
    verifier.canVerify(Algorithm.PS512);
    verifier.verify(Algorithm.PS256, messageBytes, signature);
  }

  @Test
  public void rsa_pss_public() throws Exception {
    // RSA PSS public key
    RSAPublicKey publicKey = PEM.decode(Paths.get("src/test/resources/rsa_pss_public_key_2048.pem")).getPublicKey();
    // Note that the alg property in the JWK is optional, and with an RSA key we don't know the algorithm.
    // - This key could be used with PS256, PS384 or PS512.
    assertJSONEquals(JSONWebKey.build(publicKey), "src/test/resources/jwk/rsa_pss_public_key_2048.json");

    // X.509 cert, the certificate will contain the algorithm 'SHA256withRSAandMGF1' so we will expect PS256 in the JWK
    Certificate certificate = PEM.decode(Paths.get("src/test/resources/rsa_pss_public_key_2048_certificate.pem")).certificate;
    assertJSONEquals(JSONWebKey.build(certificate), "src/test/resources/jwk/rsa_pss_public_key_2048_certificate.json");
  }

  @Test
  public void embedded_jwk() {
    JWT jwt = new JWT();
    jwt.addClaim("foo", "bar");

    RSAPrivateKey privateKey = PEM.decode(Paths.get("src/test/resources/rsa_private_key_2048.pem")).getPrivateKey();
    RSAPublicKey publicKey = PEM.decode(Paths.get("src/test/resources/rsa_public_key_2048.pem")).getPublicKey();
    JSONWebKey jwk = JSONWebKey.build(publicKey);

    Signer signer = RSASigner.newSHA256Signer(privateKey);
    String encodedJWT = JWT.getEncoder().encode(jwt, signer, h -> {
      h.set("cty", "application/json");
      h.set("jwk", jwk);
    });

    Header header = JWTUtils.decodeHeader(encodedJWT);
    assertEquals(header.get("cty"), "application/json");
    assertEquals(((Map<?, ?>) header.get("jwk")).get("e"), jwk.e);
    assertEquals(((Map<?, ?>) header.get("jwk")).get("kty"), jwk.kty.name());
    assertEquals(((Map<?, ?>) header.get("jwk")).get("n"), jwk.n);
    assertEquals(((Map<?, ?>) header.get("jwk")).get("use"), jwk.use);
  }

  @Test
  public void rsa_public() throws Exception {
    // PKCS#1 RSA PEM Encoded Public Key
    RSAPublicKey pkcs1PublicKey = PEM.decode(Paths.get("src/test/resources/rsa_public_key_2048.pem")).getPublicKey();
    assertJSONEquals(JSONWebKey.build(pkcs1PublicKey), "src/test/resources/jwk/rsa_public_key_2048.json");

    // X.509 RSA PEM Encoded Public Key
    RSAPublicKey x509PublicKey = PEM.decode(Paths.get("src/test/resources/rsa_public_key_x509.pem")).getPublicKey();
    assertJSONEquals(JSONWebKey.build(x509PublicKey), "src/test/resources/jwk/rsa_public_key_x509.json");

    // X.509 PEM encoded
    Certificate cert1 = PEM.decode(Paths.get("src/test/resources/rsa_certificate_2048.pem")).certificate;
    assertJSONEquals(JSONWebKey.build(cert1), "src/test/resources/jwk/rsa_certificate_2048.json");

    // Perform the same test again using a PEM version of the certificate to ensure we get the x5t
    assertJSONEquals(JSONWebKey.build(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_certificate_2048.pem")))), "src/test/resources/jwk/rsa_certificate_2048.json");

    // X509 certificate with a chain, not yet calculating the x5c chain
    Certificate cert2 = PEM.decode(Paths.get("src/test/resources/rsa_certificate_gd_bundle_g2.pem")).certificate;
    assertJSONEquals(JSONWebKey.build(cert2), "src/test/resources/jwk/rsa_certificate_gd_bundle_g2.json");
  }

  @Test(invocationCount = 100)
  public void eddsa_private() throws Exception {
    // ed25519
    EdECPrivateKey key25519 = PEM.decode(Paths.get("src/test/resources/ed_dsa_ed25519_private_key.pem")).getPrivateKey();
    assertJSONEquals(JSONWebKey.build(key25519), "src/test/resources/jwk/ed_dsa_ed25519_private_key.json");

    // ed448
    EdECPrivateKey key448 = PEM.decode(Paths.get("src/test/resources/ed_dsa_ed448_private_key.pem")).getPrivateKey();
    assertJSONEquals(JSONWebKey.build(key448), "src/test/resources/jwk/ed_dsa_ed448_private_key.json");
  }

  @Test(invocationCount = 100)
  public void eddsa_public() throws Exception {
    // ed25519
    EdECPublicKey key25519 = PEM.decode(Paths.get("src/test/resources/ed_dsa_ed25519_public_key.pem")).getPublicKey();
    assertJSONEquals(JSONWebKey.build(key25519), "src/test/resources/jwk/ed_dsa_ed25519_public_key.json");

    // X.509 PEM encoded
    Certificate cert25519 = PEM.decode(Paths.get("src/test/resources/ed_dsa_ed25519_certificate.pem")).certificate;
    assertJSONEquals(JSONWebKey.build(cert25519), "src/test/resources/jwk/ed_dsa_ed25519_certificate.json");

    // ed448
    EdECPublicKey key448 = PEM.decode(Paths.get("src/test/resources/ed_dsa_ed448_public_key.pem")).getPublicKey();
    assertJSONEquals(JSONWebKey.build(key448), "src/test/resources/jwk/ed_dsa_ed448_public_key.json");

    // X.509 PEM encoded
    Certificate cert448 = PEM.decode(Paths.get("src/test/resources/ed_dsa_ed448_certificate.pem")).certificate;
    assertJSONEquals(JSONWebKey.build(cert448), "src/test/resources/jwk/ed_dsa_ed448_certificate.json");
  }
}
