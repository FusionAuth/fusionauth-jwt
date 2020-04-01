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

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

/**
 * @author Daniel DeGroff
 */
public class DerValue {
  private final DerInputStream value;

  public Tag tag;

  public DerValue(Tag tag, byte[] value) {
    this.tag = tag;
    this.value = new DerInputStream(value);
  }

  public DerValue(int tag, byte[] value) {
    this.tag = new Tag(tag);
    this.value = new DerInputStream(value);
  }

  public DerValue(BigInteger integer) {
    this.tag = new Tag(Tag.Integer);
    this.value = new DerInputStream(integer.toByteArray());
  }

  public DerValue(int tag, DerOutputStream os) {
    this.tag = new Tag(tag);
    this.value = new DerInputStream(os.toByteArray());
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof DerValue)) return false;
    DerValue derValue = (DerValue) o;
    return tag == derValue.tag &&
        Arrays.equals(value.toByteArray(), derValue.value.toByteArray());
  }

  public BigInteger getBigInteger(boolean signed) {
    return signed ? new BigInteger(value.toByteArray()) : new BigInteger(1, value.toByteArray());
  }

  public BigInteger getBigInteger() {
    return getBigInteger(true);
  }

  public String getBitString() {
    if (tag.value != Tag.BitString) {
      return null;
    }

    StringBuilder sb = new StringBuilder();
    byte[] bytes = value.toByteArray();

    // Strip off the ignore byte and decode the Bit String
    int ignoreByte = bytes[0];
    for (int i = 1; i < bytes.length; i++) {
      if (i == bytes.length - 1 && ignoreByte != 0) {
        // If ignore byte is not 0, then on the last byte ignore the last n bits
        int b = (bytes[i] & 0xFF) >> ignoreByte;
        sb.append(String.format("%" + (8 - ignoreByte) + "s", (Integer.toBinaryString(b))).replace(' ', '0'));
      } else {
        sb.append(String.format("%8s", (Integer.toBinaryString(bytes[i] & 0xFF))).replace(' ', '0'));
      }
    }

    return sb.toString();
  }

  public int getLength() {
    return value.length;
  }

  public ObjectIdentifier getOID() throws IOException {
    return value.getOID();
  }

  public BigInteger getPositiveBigInteger() {
    return getBigInteger(false);
  }

  @Override
  public int hashCode() {
    int result = Objects.hash(tag);
    result = 31 * result + Arrays.hashCode(value.toByteArray());
    return result;
  }

  public byte[] toByteArray() {
    return value.toByteArray();
  }

  @Override
  public String toString() {
    if (tag.tagClass == TagClass.ContextSpecific) {
      return tag.toString();
    }

    return tag.getName() + ", length=" + value.length;
  }
}
