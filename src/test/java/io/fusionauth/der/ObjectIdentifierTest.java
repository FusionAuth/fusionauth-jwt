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

package io.fusionauth.der;

import io.fusionauth.jwt.BaseJWTTest;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * @author Daniel DeGroff
 */
public class ObjectIdentifierTest extends BaseJWTTest {
  @Test
  public void decode() throws Exception {
    // EC
    assertEquals(decode(0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01), "1.2.840.10045.2.1");

    // EC SHA-256, SHA-384, SHA-512
    assertEquals(decode(0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07), "1.2.840.10045.3.1.7");
    assertEquals(decode(0x2B, 0x81, 0x04, 0x00, 0x22), "1.3.132.0.34");
    assertEquals(decode(0x2B, 0x81, 0x04, 0x00, 0x23), "1.3.132.0.35");

    // RSA
    assertEquals(decode(0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01), "1.2.840.113549.1.1.1");

    // RSA SHA-256, SHA-384, SHA-512
    assertEquals(decode(0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B), "1.2.840.113549.1.1.11");
    assertEquals(decode(0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C), "1.2.840.113549.1.1.12");
    assertEquals(decode(0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D), "1.2.840.113549.1.1.13");

    // Other OIDs that we should be able to decode
    assertEquals(decode(0x51, 0x01), "2.1.1");
    assertEquals(decode(0x51, 0x03, 0x00, 0x01), "2.1.3.0.1");
    assertEquals(decode(0x2B, 0x06, 0x01, 0x04, 0x01, 0xAE, 0x23, 0x01, 0x03, 0x01), "1.3.6.1.4.1.5923.1.3.1");
    assertEquals(decode(0x2B, 0x06, 0x01, 0x04, 0x01, 0x9A, 0x2F, 0x02, 0x01, 0x02, 0x04, 0x01, 0x02, 0x01, 0x11), "1.3.6.1.4.1.3375.2.1.2.4.1.2.1.17");

    // Made up OID to test
    assertEquals(decode(0x53, 0x06, 0x01, 0x04, 0x01, 0xAE, 0x23, 0x01, 0x03, 0x01), "2.3.6.1.4.1.5923.1.3.1");
    assertEquals(decode(0x53, 0x06, 0x86, 0xF4, 0x61, 0x86, 0xE7, 0x3D, 0x01, 0x87, 0xA5, 0x7D, 0x01, 0x03, 0x01), "2.3.6.113249.111549.1.119549.1.3.1");

    // Test max INT - 2,147,483,647
    // - We are not supporting this configuration currently. Expect an exception.
    expectException(DerDecodingException.class, ()
        -> assertEquals(decode(0x51, 0x87, 0xFF, 0xFF, 0xFF, 0x7F, 0x01), "2.1.2147483647.1"));
  }

  private String decode(int... array) throws DerDecodingException {
    byte[] bytes = new byte[array.length];
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = (byte) array[i];
    }

    return new ObjectIdentifier(bytes).decode();
  }
}
