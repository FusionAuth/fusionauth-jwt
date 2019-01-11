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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * @author Daniel DeGroff
 */
public class DerInputStream {
  public ByteArrayInputStream data;

  public int length;

  public DerInputStream(DerValue dervalue) {
    this(dervalue.toByteArray());
  }

  public DerInputStream(byte[] bytes) {
    data = new ByteArrayInputStream(bytes);
    length = bytes.length;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof DerInputStream)) return false;
    DerInputStream that = (DerInputStream) o;
    return length == that.length &&
        Arrays.equals(toByteArray(), that.toByteArray());
  }

  public ObjectIdentifier getOID() throws DerDecodingException {
    int tag = data.read();
    if (tag != Tag.ObjectIdentifier) {
      throw new DerDecodingException("Expected to find an Object Identifier tag " + Tag.ObjectIdentifier + " (" + Tag.hexString(Tag.ObjectIdentifier) + ") " +
          "but found " + tag + " (" + Tag.hexString(tag) + ")");
    }

    int length = readLength();
    if (length > data.available()) {
      throw new DerDecodingException("A DER encoded value indicates it is [" + length + "] bytes long, but only [" + data.available() + "] are available to read in the input stream length. Unable " +
          "to read the Object Identifier from the stream.");
    }

    byte[] buf = new byte[length];
    //noinspection ResultOfMethodCallIgnored
    data.read(buf, 0, length);
    return new ObjectIdentifier(buf);
  }

  public DerValue[] getSequence() throws DerDecodingException {
    int tag = data.read();
    if (tag != Tag.Sequence) {
      throw new DerDecodingException("Expected to find a sequence tag " + Tag.Sequence + " (" + Tag.hexString(Tag.Sequence) + ") " +
          "but found " + tag + " (" + Tag.hexString(tag) + ")");
    }

    int length = readLength();
    byte[] sequence = copyBytes(length);
    return getValuesFromBytes(sequence);
  }

  @Override
  public int hashCode() {
    return Objects.hash(toByteArray(), length);
  }

  public DerValue readDerValue() throws DerDecodingException {
    int tag = data.read();
    int length = readLength();
    byte[] bytes = copyBytes(length);
    return new DerValue(tag, bytes);
  }

  public byte[] toByteArray() {
    try {
      byte[] buffer = new byte[length];
      data.reset();
      int actualLength = data.read(buffer);
      if (actualLength != length) {
        throw new IOException("Failed to read the entire byte array. Expected to read " + length + " bytes, but only read " + actualLength + ".");
      }
      return buffer;
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private byte[] copyBytes(int l) {
    byte[] seq = new byte[l];
    for (int i = 0; i < l; i++) {
      seq[i] = (byte) data.read();
    }

    return seq;
  }

  private DerValue[] getValuesFromBytes(byte[] bytes) throws DerDecodingException {
    List<DerValue> result = new ArrayList<>();

    int index = 0;
    while (index < bytes.length) {
      ByteArrayInputStream stream = new ByteArrayInputStream(bytes, index, bytes.length);
      int avail = stream.available();

      Tag tag = new Tag(stream.read());
      int length = readLength(stream);

      // Account for the length of the tag and length in bytes
      // - Tag is always one byte, the length is variable
      int adjustment = Math.abs(stream.available() - avail);

      byte[] buf = new byte[length];
      for (int i = 0; i < length; i++) {
        buf[i] = (byte) stream.read();
      }

      result.add(new DerValue(tag, buf));
      index = index + length + adjustment;
    }

    return result.toArray(new DerValue[]{});
  }

  private int readLength(InputStream inputStream) throws DerDecodingException {
    try {
      int b = inputStream.read();
      if (b == -1) {
        throw new IOException("Invalid DER encoding, unable to read length of -1.");
      }

      int length = b;
      int remaining = length & 0x80; // 0b1000000 or 128
      if (remaining == 0) {
        // Length is less than 128, the length is full represented in the first byte
        return length;
      }

      remaining = length & 0x7F; // 0b1000001 or 127
      if (remaining == 0) {
        return -1;
      }

      //noinspection ConstantConditions
      if (remaining < 0) {
        throw new IOException("Invalid DER encoding.");
      } else if (remaining > 4) {
        throw new IOException("Invalid DER encoding, the value is too big.");
      }

      length = inputStream.read() & 0xFF; // 0b11111111 or 255
      remaining = remaining - 1;
      if (length == 0) {
        throw new IOException("Redundant length bytes found");
      }

      while (remaining > 0) {
        remaining = remaining - 1;
        length <<= 8;
        length += inputStream.read() & 0xFF;  // 0b11111111 or255
      }

      if (length < 0) {
        throw new IOException("Invalid length bytes");
      } else if (length <= 127) {
        throw new IOException("Should use short form for length");
      }

      return length;
    } catch (IOException e) {
      throw new DerDecodingException(e);
    }
  }

  private int readLength() throws DerDecodingException {
    return readLength(data);
  }
}
