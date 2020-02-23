/*
 * Copyright (c) 2018-2020, FusionAuth, All Rights Reserved
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

import java.util.Objects;

/**
 * This object models a ASN.1 DER Tag.
 *
 * @author Daniel DeGroff
 */
public class Tag {
  /**
   * Bit String Tag
   */
  public static final int BitString = 3;

  /**
   * Integer Tag
   */
  public static final int Integer = 2;

  /**
   * Null Tag
   */
  public static final int Null = 5;

  /**
   * Object Identifier Tag
   */
  public static final int ObjectIdentifier = 6;

  /**
   * Octet String Tag
   */
  public static final int OctetString = 4;

  /**
   * PrintableString Tag
   * <p>
   * 19 decimal, 0x13 hex
   * </p>
   */
  public static final int PrintableString = 19;

  /**
   * Sequence Tag
   * <p>
   * 16 decimal, 0x10 hex, 0b00010000 binary
   * </p>
   * Because the Sequence tag is always in a constructed form (not primitive), the tag will present as <code>0x30</code> because
   * the 6th bit is a <code>1</code> indicating a constructed form. So the raw sequence of <code>0b00010000</code> becomes
   * <code>0b00110000</code> which is <code>48</code> decimal.
   */
  public static final int Sequence = 48;

  /**
   * Set and Set of
   * <p>
   * 17 decimal, 0x11 hex
   * </p>
   */
  public static final int Set = 17;

  /**
   * UTCTime Tag
   * <p>
   * 23 decimal, 0x17 hex
   * </p>
   */
  public static final int UTCTime = 23;

  /**
   * True if this Tag is primitive. False if this Tag is constructed.
   */
  public final boolean primitive;

  /**
   * The raw byte read from the DER encoded array. This byte includes the class, form and tag number.
   */
  public final byte rawByte;

  /**
   * The class of this tag read from bits 8 and 7 of the raw byte.
   */
  public final TagClass tagClass;

  /**
   * The tag value in decimal. This value will only represent the decimal value of bits 5 to 1.
   *
   * <p>
   * For example, if this is a sequence tag, this value will be <code>16</code> and you should expect <code>primitive</code>
   * to be false. If you want the raw byte which will be <code>48</code> or <code>0x30</code> you can read <code>rawByte</code>.
   * </p>
   */
  public final int value;

  /**
   * Construct a new tag from the tag byte in the DER byte array. The following depicts the layout of the tag byte.
   *
   * <pre>
   *   ---------------------------------------------------------
   *   |  b8  |  b7  |  b6  |  b5  |  b4  |  b3  |  b2  |  b1  |
   *   ---------------------------------------------------------
   *      |______|      |      |___________________________|
   *        |           |                         |
   *        |           |-- [0] Primitive         |
   *        |           |-- [1] Constructed       |
   *        |                                  Tag Number (value)
   *        | Class
   *        |---------------------------
   *        |-- 0  0  Universal
   *        |-- 0  1  Application
   *        |-- 1  0  Context Specific
   *        |-- 1  1  Private
   * </pre>
   *
   * @param value the tag value from the DER byte array
   */
  public Tag(int value) {
    // Hold the raw value provided
    rawByte = (byte) value;
    tagClass = setTagClass(value);

    // The 6th bit indicates if this tag is primitive or constructed
    primitive = (rawByte & 0b00100000) == 0;

    // The last 5 bits are the tag
    this.value = value & 0b00011111;
  }

  static String hexString(int value) {
    return "0x" + String.format("%02x", value).toUpperCase();
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof Tag)) return false;
    Tag tag = (Tag) o;
    return rawByte == tag.rawByte;
  }

  public String getName() {
    switch (rawByte) {
      case Integer:
        return "Integer";
      case BitString:
        return "Bit String";
      case Null:
        return "Null";
      case ObjectIdentifier:
        return "Object Identifier";
      case OctetString:
        return "Octet String";
      case PrintableString:
        return "PrintableString";
      case Sequence:
        return "Sequence";
      case Set:
        return "Set";
      case UTCTime:
        return "UTCTime";
      default:
        return "Other";
    }
  }

  @Override
  public int hashCode() {
    return Objects.hash(rawByte);
  }

  /**
   * @param tag a tag
   * @return true if this tag has the same value as requested
   */
  public boolean is(int tag) {
    return value == (tag & 0b00011111);
  }

  public boolean isConstructed() {
    return !primitive;
  }

  public boolean isPrimitive() {
    return primitive;
  }

  @Override
  public String toString() {
    if (tagClass == TagClass.ContextSpecific) {
      return "[" + value + "]";
    }

    return value + " [" + getName() + ", " + hexString() + "]";
  }

  private TagClass setTagClass(int value) {
    TagClass tagClass = null;
    for (TagClass tc : TagClass.values()) {
      if ((value & 0b11000000) == tc.value) {
        tagClass = tc;
        break;
      }
    }

    if (tagClass == null) {
      throw new IllegalArgumentException("Invalid tag value " + value + ", the tag does not appear to fit into one of the expected classes");
    }

    return tagClass;
  }

  String hexString() {
    return "0x" + String.format("%02x", value).toUpperCase();
  }
}
