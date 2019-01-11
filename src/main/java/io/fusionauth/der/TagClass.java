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

/**
 * The 2 left most bits of the tag byte indicate the tag class.
 *
 * <pre>
 *   b8     b7    Class               Hex        Decimal
 *   -----------------------------------------------------
 *   0      0    Universal            0x00       0
 *   0      1    Application          0x40       64
 *   1      0    Context Specific     0x80       128
 *   1      1    Private              0xC0       192
 * </pre>
 *
 * @author Daniel DeGroff
 */
public enum TagClass {
  /**
   * Universal
   */
  Universal(0b00000000), // 0
  /**
   * Application
   */
  Application(0b01000000), // 64

  /**
   * Context Specific
   */
  ContextSpecific(0b10000000), // 128

  /**
   * Private
   */
  Private(0b11000000); // 192

  public int value;

  TagClass(int value) {
    this.value = value;
  }
}
