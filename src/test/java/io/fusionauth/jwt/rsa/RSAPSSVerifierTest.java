/*
 * Copyright (c) 2017-2019, FusionAuth, All Rights Reserved
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

package io.fusionauth.jwt.rsa;

import io.fusionauth.jwt.BaseTest;
import io.fusionauth.jwt.InvalidKeyLengthException;
import io.fusionauth.jwt.RequiresAlgorithm;
import io.fusionauth.jwt.Verifier;
import io.fusionauth.jwt.domain.Algorithm;
import io.fusionauth.jwt.domain.JWT;
import io.fusionauth.pem.domain.PEM;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

/**
 * @author Daniel DeGroff
 */
public class RSAPSSVerifierTest extends BaseTest {
  @Test
  public void test_public_pem_parsing() {
    Arrays.asList(
        "rsa_public_certificate_2048.pem",
        "rsa_public_key_2048.pem",
        "rsa_public_key_2048_with_meta.pem",
        "rsa_public_key_3072.pem",
        "rsa_public_key_4096.pem")
        .forEach(fileName -> {
          // Take a String arg
          assertRSAPSAVerifier(RSAPSSVerifier.newVerifier(getPath(fileName)));
          // Take a Path arg
          assertRSAPSAVerifier(RSAPSSVerifier.newVerifier(readFile(fileName)));
          // Take a byte[] arg
          assertRSAPSAVerifier(RSAPSSVerifier.newVerifier(readFile(fileName).getBytes(StandardCharsets.UTF_8)));
          // Take a public key arg
          assertRSAPSAVerifier(RSAPSSVerifier.newVerifier((RSAPublicKey) PEM.decode(readFile(fileName)).getPublicKey()));
        });

    // Public key parsing also works with private keys since the public key is encoded in the private
    Arrays.asList(
        "rsa_private_key_2048.pem",
        "rsa_private_key_2048_with_meta.pem",
        "rsa_private_key_3072.pem",
        "rsa_private_key_4096.pem")
        .forEach((fileName -> {
          // Take a String arg
          assertRSAPSAVerifier(RSAPSSVerifier.newVerifier(getPath(fileName)));
          // Take a Path arg
          assertRSAPSAVerifier(RSAPSSVerifier.newVerifier(readFile(fileName)));
          // Take a byte[] arg
          assertRSAPSAVerifier(RSAPSSVerifier.newVerifier(readFile(fileName).getBytes(StandardCharsets.UTF_8)));
          // Take a public key arg
          assertRSAPSAVerifier(RSAPSSVerifier.newVerifier((RSAPublicKey) PEM.decode(readFile(fileName)).getPublicKey()));
        }));
  }

  @Test
  public void test_rsa_1024_pem() {
    try {
      RSAPSSVerifier.newVerifier(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_public_key_1024.pem"))));
      Assert.fail("Expected [InvalidKeyLengthException] exception");
    } catch (InvalidKeyLengthException ignore) {
    } catch (Exception e) {
      Assert.fail("Unexpected exception", e);
    }
  }

  @Test
  @RequiresAlgorithm("RSASSA-PSS")
  public void control() {
    String encodedJWT = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.hZnl5amPk_I3tb4O-Otci_5XZdVWhPlFyVRvcqSwnDo_srcysDvhhKOD01DigPK1lJvTSTolyUgKGtpLqMfRDXQlekRsF4XhAjYZTmcynf-C-6wO5EI4wYewLNKFGGJzHAknMgotJFjDi_NCVSjHsW3a10nTao1lB82FRS305T226Q0VqNVJVWhE4G0JQvi2TssRtCxYTqzXVt22iDKkXeZJARZ1paXHGV5Kd1CljcZtkNZYIGcwnj65gvuCwohbkIxAnhZMJXCLaVvHqv9l-AAUV7esZvkQR1IpwBAiDQJh4qxPjFGylyXrHMqh5NlT_pWL2ZoULWTg_TJjMO9TuQ";
    String publicKeyPEM = "-----BEGIN PUBLIC KEY-----\n" +
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv\n" +
        "vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc\n" +
        "aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy\n" +
        "tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0\n" +
        "e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb\n" +
        "V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9\n" +
        "MwIDAQAB\n" +
        "-----END PUBLIC KEY-----";


    Verifier verifier = RSAPSSVerifier.newVerifier(publicKeyPEM);
    JWT jwt = JWT.getDecoder().decode(encodedJWT, verifier);
    assertNotNull(jwt);
    assertEquals(jwt.subject, "1234567890");
    assertEquals(jwt.getString("name"), "John Doe");
    assertEquals(jwt.getBoolean("admin"), Boolean.TRUE);
  }

  private void assertRSAPSAVerifier(Verifier verifier) {
    assertFalse(verifier.canVerify(Algorithm.ES256));
    assertFalse(verifier.canVerify(Algorithm.ES384));
    assertFalse(verifier.canVerify(Algorithm.ES512));

    assertFalse(verifier.canVerify(Algorithm.HS256));
    assertFalse(verifier.canVerify(Algorithm.HS384));
    assertFalse(verifier.canVerify(Algorithm.HS512));

    assertTrue(verifier.canVerify(Algorithm.PS256));
    assertTrue(verifier.canVerify(Algorithm.PS384));
    assertTrue(verifier.canVerify(Algorithm.PS512));

    assertFalse(verifier.canVerify(Algorithm.RS256));
    assertFalse(verifier.canVerify(Algorithm.RS384));
    assertFalse(verifier.canVerify(Algorithm.RS512));
  }
}
