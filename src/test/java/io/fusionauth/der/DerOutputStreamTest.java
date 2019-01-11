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

package io.fusionauth.der;

import org.testng.annotations.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

/**
 * @author Daniel DeGroff
 */
public class DerOutputStreamTest {
  @Test
  public void long_binaryString() throws Exception {
    // Test each threshold to get 1, 2, 3, and 4 byte lengths
    for (int length : new int[]{127, 255, 65_535, 16_777_215, 167_77_217}) {
      String input = new String(new char[length]).replace('\0', '$');
      byte[] bytes = input.getBytes(StandardCharsets.UTF_8);
      DerValue value = new DerValue(Tag.BitString, bytes);

      DerOutputStream os = new DerOutputStream();
      os.writeValue(value);
      byte[] output = os.toByteArray();

      assertNotNull(output);
      if (length < 128) {
        // 1 byte used for size
        assertEquals(output.length, length + 2);
        assertEquals(output[1], bytes.length, "For length length [" + length + "]");
      } else if (length < 256) {
        // 1 additional byte used for size
        assertEquals(output.length, length + 3);
        assertEquals(ByteBuffer.wrap(new byte[]{0, output[2]}).getShort(), bytes.length, "For length length [" + length + "]");
      } else if (length < 65_536) {
        // 2 additional bytes used for size
        assertEquals(output.length, length + 4);
        assertEquals(ByteBuffer.wrap(new byte[]{0, 0, output[2], output[3]}).getInt(), bytes.length, "For length length [" + length + "]");
      } else if (length < 16_777_216) {
        // 3 additional bytes used for size
        assertEquals(output.length, length + 5);
        assertEquals(ByteBuffer.wrap(new byte[]{0, output[2], output[3], output[4]}).getInt(), bytes.length, "For length length [" + length + "]");
      } else {
        // 4 additional bytes used for size
        assertEquals(output.length, length + 6);
        assertEquals(ByteBuffer.wrap(new byte[]{output[2], output[3], output[4], output[5]}).getInt(), bytes.length, "For length length [" + length + "]");
      }
    }
  }
}
