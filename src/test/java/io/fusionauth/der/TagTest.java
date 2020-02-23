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

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * @author Daniel DeGroff
 */
public class TagTest {
  @Test
  public void binaryAssertions() {
    // I know these won't change - this is for (my) understanding.

    assertEquals(0b00000000, 0); // General
    assertEquals(0b01000000, 64); // Application
    assertEquals(0b10000000, 128); // Context Specific
    assertEquals(0b11000000, 192); // Private

    // Context specific - Integer
    assertEquals(0b10000010, 130);
    // Context specific - Object Identifier
    assertEquals(0b10000110, 134);
  }

  @Test
  public void tag() {
    // Universal primitive Integer
    assertEquals(new Tag(0b00000010).tagClass, TagClass.Universal);
    assertTrue(new Tag(0b00000010).is(Tag.Integer));
    assertTrue(new Tag(0b00000010).isPrimitive());

    // Context specific primitive Integer
    assertEquals(new Tag(0b10000010).tagClass, TagClass.ContextSpecific);
    assertTrue(new Tag(0b10000010).is(Tag.Integer));
    assertTrue(new Tag(0b10000010).isPrimitive());

    // Universal primitive Object Identifier
    assertEquals(new Tag(0b00000110).tagClass, TagClass.Universal);
    assertTrue(new Tag(0b00000110).is(Tag.ObjectIdentifier));
    assertTrue(new Tag(0b00000110).isPrimitive());

    // Context specific primitive Object Identifier
    assertEquals(new Tag(0b10000110).tagClass, TagClass.ContextSpecific);
    assertTrue(new Tag(0b10000110).is(Tag.ObjectIdentifier));
    assertTrue(new Tag(0b10000110).isPrimitive());

    // Universal Sequence, always constructed
    assertEquals(new Tag(0b00110000).tagClass, TagClass.Universal);
    assertTrue(new Tag(0b00110000).is(Tag.Sequence));
    assertTrue(new Tag(0b00110000).isConstructed());

    // Universal Bit String, may be both primitive and constructive  - primitive
    assertEquals(new Tag(0b00000011).tagClass, TagClass.Universal);
    assertTrue(new Tag(0b00000011).is(Tag.BitString));
    assertTrue(new Tag(0b00000011).isPrimitive());

    // Universal Bit String, may be both primitive and constructive - constructed
    assertEquals(new Tag(0b00100011).tagClass, TagClass.Universal);
    assertTrue(new Tag(0b00100011).is(Tag.BitString));
    assertTrue(new Tag(0b00100011).isConstructed());

    // Universal Octet String, may be both primitive and constructive - primitive
    assertEquals(new Tag(0b00000100).tagClass, TagClass.Universal);
    assertTrue(new Tag(0b00000100).is(Tag.OctetString));
    assertTrue(new Tag(0b00000100).isPrimitive());

    // Universal Octet String, may be both primitive and constructive - constructed
    assertEquals(new Tag(0b00100100).tagClass, TagClass.Universal);
    assertTrue(new Tag(0b00100100).is(Tag.OctetString));
    assertTrue(new Tag(0b00100100).isConstructed());

    // Actual values from a EC Private key
    assertEquals(new Tag(0xA0).value, 0);
    assertEquals(new Tag(0xA0).tagClass, TagClass.ContextSpecific);

    assertEquals(new Tag(0xA1).value, 1);
    assertEquals(new Tag(0xA1).tagClass, TagClass.ContextSpecific);

    // Universal PrintableString
    assertEquals(new Tag(0b00010011).tagClass, TagClass.Universal);
    assertTrue(new Tag(0b00010011).is(Tag.PrintableString));
    assertTrue(new Tag(0b00010011).isPrimitive());

    // Universal Set
    assertEquals(new Tag(0b00010001).tagClass, TagClass.Universal);
    assertTrue(new Tag(0b00010001).is(Tag.Set));
    assertTrue(new Tag(0b00010001).isPrimitive());

    // Universal UTCTime
    assertEquals(new Tag(0b00010111).tagClass, TagClass.Universal);
    assertTrue(new Tag(0b00010111).is(Tag.UTCTime));
    assertTrue(new Tag(0b00010111).isPrimitive());
  }
}
