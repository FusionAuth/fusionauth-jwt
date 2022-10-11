/*
 * Copyright (c) 2018-2022, FusionAuth, All Rights Reserved
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import io.fusionauth.jwt.BaseJWTTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import static org.testng.AssertJUnit.fail;

/**
 * @author Daniel DeGroff
 */
public class ObjectIdentifierTest extends BaseJWTTest {
  private Options option;

  @Test(dataProvider = "options")
  public void decodeAndEncode(Options option) throws Exception {
    // Note, using a data provider to either encode or decode on a single pass so that it is easier to debug and get the failure in either direction.
    this.option = option;

    // EC
    assertEquality("1.2.840.10045.2.1", 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01);

    // EC SHA-256, SHA-384, SHA-512
    assertEquality("1.2.840.10045.3.1.7", 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07);
    assertEquality("1.3.132.0.34", 0x2B, 0x81, 0x04, 0x00, 0x22);
    assertEquality("1.3.132.0.35", 0x2B, 0x81, 0x04, 0x00, 0x23);

    // RSA
    assertEquality("1.2.840.113549.1.1.1", 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01);

    // RSA SHA-256, SHA-384, SHA-512
    assertEquality("1.2.840.113549.1.1.11", 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B);
    assertEquality("1.2.840.113549.1.1.12", 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C);
    assertEquality("1.2.840.113549.1.1.13", 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D);

    // Other OIDs that we should be able to decode
    assertEquality("2.1.1", 0x51, 0x01);
    assertEquality("2.5.4.3", 0x55, 0x04, 0x03);
    assertEquality("2.1.3.0.1", 0x51, 0x03, 0x00, 0x01);
    assertEquality("1.3.6.1.4.1.5923.1.3.1", 0x2B, 0x06, 0x01, 0x04, 0x01, 0xAE, 0x23, 0x01, 0x03, 0x01);
    assertEquality("1.3.6.1.4.1.3375.2.1.2.4.1.2.1.17", 0x2B, 0x06, 0x01, 0x04, 0x01, 0x9A, 0x2F, 0x02, 0x01, 0x02, 0x04, 0x01, 0x02, 0x01, 0x11);

    // Made up OID to test
    assertEquality("2.3.6.1.4.1.5923.1.3.1", 0x53, 0x06, 0x01, 0x04, 0x01, 0xAE, 0x23, 0x01, 0x03, 0x01);
    assertEquality("2.3.6.113249.111549.1.119549.1.3.1", 0x53, 0x06, 0x86, 0xF4, 0x61, 0x86, 0xE7, 0x3D, 0x01, 0x87, 0xA5, 0x7D, 0x01, 0x03, 0x01);

    // Test max INT - 2,147,483,647
    // - We are not supporting this configuration currently. Expect an exception.
    if (option == Options.decode) {
      expectException(DerDecodingException.class, ()
          -> assertEquality("2.1.2147483647.1", 0x51, 0x87, 0xFF, 0xFF, 0xFF, 0x7F, 0x01));
    } else {
      expectException(ArrayIndexOutOfBoundsException.class, ()
          -> assertEquality("2.1.2147483647.1", 0x51, 0x87, 0xFF, 0xFF, 0xFF, 0x7F, 0x01));
    }
  }

  @DataProvider(name = "options")
  public Object[][] options() {
    return new Object[][]{
        {Options.encode},
        {Options.decode}
    };
  }

  private void assertEquality(String expectedOid, int... ints) throws DerDecodingException {
    // Decode the hex bytes and assert that we can build the same OID string.
    if (option == Options.decode) {
      String actualOid = decode(ints);
      if (!actualOid.equals(expectedOid)) {
        fail("Expected [" + expectedOid + "] but found [" + actualOid + "]");
      }
    } else {
      // Parse the string and ensure we can build derive the same bytes
      byte[] actual = ObjectIdentifier.encode(expectedOid);
      byte[] bytes = bytes(ints);
      if (!Arrays.equals(actual, bytes)) {
        fail("Expected [" + bytesToStringArray(bytes) + "] but found [" + bytesToStringArray(actual) + "]");
      }
    }
  }

  private byte[] bytes(int... array) {
    byte[] bytes = new byte[array.length];
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = (byte) array[i];
    }

    return bytes;
  }

  private String bytesToStringArray(byte[] bytes) {
    List<Byte> pretty = new ArrayList<>();
    for (byte b : bytes) {
      pretty.add(b);
    }

    return pretty.stream().map(b -> String.format("0x%02X", b)).collect(Collectors.joining(", "));
  }

  private String decode(int... array) throws DerDecodingException {
    byte[] bytes = new byte[array.length];
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = (byte) array[i];
    }

    return new ObjectIdentifier(bytes).decode();
  }

  private enum Options {
    encode,
    decode
  }
}
