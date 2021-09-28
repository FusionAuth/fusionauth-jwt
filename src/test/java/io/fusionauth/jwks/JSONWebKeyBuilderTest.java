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
import io.fusionauth.jwt.BaseJWTTest;
import io.fusionauth.jwt.JWTUtils;
import io.fusionauth.jwt.Signer;
import io.fusionauth.jwt.domain.Header;
import io.fusionauth.jwt.domain.JWT;
import io.fusionauth.jwt.rsa.RSASigner;
import io.fusionauth.pem.domain.PEM;
import org.testng.annotations.Test;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Map;

import static org.testng.Assert.assertEquals;

/**
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
}
