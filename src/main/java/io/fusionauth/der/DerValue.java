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

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Locale;
import java.util.Objects;
import java.util.TimeZone;

import static java.nio.charset.StandardCharsets.ISO_8859_1;

/**
 * @author Daniel DeGroff
 */
public class DerValue {
  private static final SimpleDateFormat GENERALIZED_DATE_FORMAT;

  private static final SimpleDateFormat UTC_DATE_FORMAT;

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

  public DerValue(Tag tag, DerOutputStream os) {
    this.tag = tag;
    this.value = new DerInputStream(os.toByteArray());
  }

  public DerValue(int tag, DerOutputStream os) {
    this.tag = new Tag(tag);
    this.value = new DerInputStream(os.toByteArray());
  }

  public static DerValue newASCIIString(String s) {
    return new DerValue(Tag.PrintableString, s.getBytes(StandardCharsets.US_ASCII));
  }

  public static DerValue newBitString(byte[] bytes) {
    return new DerValue(Tag.BitString, ByteBuffer.allocate(bytes.length + 1)
                                                 // All bytes are used, no ignore byte
                                                 .put((byte) 0)
                                                 // Original byte array
                                                 .put(bytes)
                                                 .array());
  }

  public static DerValue newGeneralizedTime(Date date) {
    return new DerValue(Tag.GeneralizedTime, GENERALIZED_DATE_FORMAT.format(date).getBytes(ISO_8859_1));
  }

  public static DerValue newNull() {
    return new DerValue(Tag.Null, new byte[]{});
  }

  public static DerValue newUTCTime(Date date) {
    return new DerValue(Tag.UTCTime, UTC_DATE_FORMAT.format(date).getBytes(ISO_8859_1));
  }

  public static DerValue newUTF8String(String s) {
    return new DerValue(Tag.UTFString, s.getBytes(StandardCharsets.UTF_8));
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof DerValue)) {
      return false;
    }
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

  public byte[] getBitStringBytes() {
    StringBuilder sb = new StringBuilder();
    byte[] bytes = value.toByteArray();
    ByteBuffer buffer = ByteBuffer.allocate(bytes.length);

    // Strip off the ignore byte and decode the Bit String
    int ignoreByte = bytes[0];
    for (int i = 1; i < bytes.length; i++) {
      if (i == bytes.length - 1 && ignoreByte != 0) {
        // If ignore byte is not 0, then on the last byte ignore the last n bits
        int b = (bytes[i] & 0xFF) >> ignoreByte;
        buffer.put((byte) b);
      } else {
        buffer.put((byte) (bytes[i] & 0xFF));
      }
    }

    return buffer.array();
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

  static {
    GENERALIZED_DATE_FORMAT = new SimpleDateFormat("yyyyMMddHHmmss'Z'", Locale.US);
    GENERALIZED_DATE_FORMAT.setTimeZone(TimeZone.getTimeZone("GMT"));

    UTC_DATE_FORMAT = new SimpleDateFormat("yyMMddHHmmss'Z'", Locale.US);
    UTC_DATE_FORMAT.setTimeZone(TimeZone.getTimeZone("GMT"));
  }
}
