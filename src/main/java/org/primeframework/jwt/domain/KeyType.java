/*
 * Copyright (c) 2016, Inversoft Inc., All Rights Reserved
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

package org.primeframework.jwt.domain;

/**
 * Available Cryptographic Algorithms for Keys as described in <a href="https://tools.ietf.org/html/rfc7518#section-6.1">RFC
 * 7518 Section 6.1</a>.
 * <p>
 * <ul> <li>ES Elliptic Curve [DDS]</li> <li>RSA as defined by  <a href="https://tools.ietf.org/html/rfc3447">RFC
 * 3447</a></li> <li>oct: Octet Sequence (used to represent symmetric keys)</li> </ul>
 * <p>
 * Currently only the RSA Key Type is implemented and supported in this library.
 *
 * @author Daniel DeGroff
 */
public enum KeyType {
  /**
   * RSA as defined by <a href="https://tools.ietf.org/html/rfc3447">RFC 3447</a>
   */
  RSA
}
