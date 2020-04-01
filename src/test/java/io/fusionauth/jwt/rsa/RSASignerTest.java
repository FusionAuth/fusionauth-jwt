/*
 * Copyright (c) 2017, FusionAuth, All Rights Reserved
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
import io.fusionauth.security.BCFIPSCryptoProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

/**
 * @author Daniel DeGroff
 */
public class RSASignerTest extends BaseTest {
  @Test
  public void test_private_pem_parsing() {
    // No kid
    assertNotNull(RSASigner.newSHA256Signer(readFile("rsa_private_key_2048.pem")));
    assertNotNull(RSASigner.newSHA256Signer(readFile("rsa_private_key_2048_with_meta.pem")));
    assertNotNull(RSASigner.newSHA256Signer(readFile("rsa_private_key_3072.pem")));
    assertNotNull(RSASigner.newSHA256Signer(readFile("rsa_private_key_4096.pem")));

    assertNotNull(RSASigner.newSHA384Signer(readFile("rsa_private_key_2048.pem")));
    assertNotNull(RSASigner.newSHA384Signer(readFile("rsa_private_key_2048_with_meta.pem")));
    assertNotNull(RSASigner.newSHA384Signer(readFile("rsa_private_key_3072.pem")));
    assertNotNull(RSASigner.newSHA384Signer(readFile("rsa_private_key_4096.pem")));

    assertNotNull(RSASigner.newSHA512Signer(readFile("rsa_private_key_2048.pem")));
    assertNotNull(RSASigner.newSHA512Signer(readFile("rsa_private_key_2048_with_meta.pem")));
    assertNotNull(RSASigner.newSHA512Signer(readFile("rsa_private_key_3072.pem")));
    assertNotNull(RSASigner.newSHA512Signer(readFile("rsa_private_key_4096.pem")));

    // With kid
    assertEquals(RSASigner.newSHA256Signer(readFile("rsa_private_key_2048.pem"), "abc").getKid(), "abc");
    assertEquals(RSASigner.newSHA256Signer(readFile("rsa_private_key_2048_with_meta.pem"), "abc").getKid(), "abc");
    assertEquals(RSASigner.newSHA256Signer(readFile("rsa_private_key_3072.pem"), "abc").getKid(), "abc");
    assertEquals(RSASigner.newSHA256Signer(readFile("rsa_private_key_4096.pem"), "abc").getKid(), "abc");

    assertEquals(RSASigner.newSHA384Signer(readFile("rsa_private_key_2048.pem"), "abc").getKid(), "abc");
    assertEquals(RSASigner.newSHA384Signer(readFile("rsa_private_key_2048_with_meta.pem"), "abc").getKid(), "abc");
    assertEquals(RSASigner.newSHA384Signer(readFile("rsa_private_key_3072.pem"), "abc").getKid(), "abc");
    assertEquals(RSASigner.newSHA384Signer(readFile("rsa_private_key_4096.pem"), "abc").getKid(), "abc");

    assertEquals(RSASigner.newSHA512Signer(readFile("rsa_private_key_2048.pem"), "abc").getKid(), "abc");
    assertEquals(RSASigner.newSHA512Signer(readFile("rsa_private_key_2048_with_meta.pem"), "abc").getKid(), "abc");
    assertEquals(RSASigner.newSHA512Signer(readFile("rsa_private_key_3072.pem"), "abc").getKid(), "abc");
    assertEquals(RSASigner.newSHA512Signer(readFile("rsa_private_key_4096.pem"), "abc").getKid(), "abc");

    // With provided crypto provider
    assertNotNull(RSASigner.newSHA256Signer(readFile("rsa_private_key_2048.pem"), new BCFIPSCryptoProvider()));
    assertNotNull(RSASigner.newSHA256Signer(readFile("rsa_private_key_2048_with_meta.pem"), new BCFIPSCryptoProvider()));
    assertNotNull(RSASigner.newSHA256Signer(readFile("rsa_private_key_3072.pem"), new BCFIPSCryptoProvider()));
    assertNotNull(RSASigner.newSHA256Signer(readFile("rsa_private_key_4096.pem"), new BCFIPSCryptoProvider()));

    assertNotNull(RSASigner.newSHA384Signer(readFile("rsa_private_key_2048.pem"), new BCFIPSCryptoProvider()));
    assertNotNull(RSASigner.newSHA384Signer(readFile("rsa_private_key_2048_with_meta.pem"), new BCFIPSCryptoProvider()));
    assertNotNull(RSASigner.newSHA384Signer(readFile("rsa_private_key_3072.pem"), new BCFIPSCryptoProvider()));
    assertNotNull(RSASigner.newSHA384Signer(readFile("rsa_private_key_4096.pem"), new BCFIPSCryptoProvider()));

    assertNotNull(RSASigner.newSHA512Signer(readFile("rsa_private_key_2048.pem"), new BCFIPSCryptoProvider()));
    assertNotNull(RSASigner.newSHA512Signer(readFile("rsa_private_key_2048_with_meta.pem"), new BCFIPSCryptoProvider()));
    assertNotNull(RSASigner.newSHA512Signer(readFile("rsa_private_key_3072.pem"), new BCFIPSCryptoProvider()));
    assertNotNull(RSASigner.newSHA512Signer(readFile("rsa_private_key_4096.pem"), new BCFIPSCryptoProvider()));
  }
}
