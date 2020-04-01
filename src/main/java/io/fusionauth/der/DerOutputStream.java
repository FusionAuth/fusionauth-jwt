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

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * @author Daniel DeGroff
 */
public class DerOutputStream {
  private final ByteArrayOutputStream os;

  public DerOutputStream() {
    os = new ByteArrayOutputStream();
  }

  public byte[] toByteArray() {
    return os.toByteArray();
  }

  public DerOutputStream writeValue(DerValue value) throws DerEncodingException {
    try {
      os.write(value.tag.rawByte);
      writeLength(value.getLength());
      os.write(value.toByteArray());
      return this;
    } catch (IOException e) {
      throw new DerEncodingException(e);
    }
  }

  private void writeLength(int length) {
    // When the length is less than 128, the length can be represented in a single byte
    // - additional bytes are necessary for values greater than or equal to 128
    if (length < 128) {
      os.write((byte) length);
    } else if (length < 256) {
      os.write(-127); // 10000001 - 1 byte to follow
      os.write((byte) length);
    } else if (length < 65536) {
      os.write(-126); // 10000010 - 2 bytes to follow
      os.write((byte) (length >> 8));
      os.write((byte) length);
    } else if (length < 16777216) {
      os.write(-125); // 10000011 - 3 bytes to follow
      os.write((byte) (length >> 16));
      os.write((byte) (length >> 8));
      os.write((byte) length);
    } else {
      os.write(-124); // 10000100 - 4 bytes to follow
      os.write((byte) (length >> 24));
      os.write((byte) (length >> 16));
      os.write((byte) (length >> 8));
      os.write((byte) length);
    }
  }
}
