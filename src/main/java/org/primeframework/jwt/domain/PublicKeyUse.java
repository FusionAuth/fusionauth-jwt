/*
 * Copyright (c) 2017, Inversoft Inc., All Rights Reserved
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
 * Public Key Use as defined by <a href="https://tools.ietf.org/html/rfc7517#section-4.2">RFC 7517 Section 4.2</a>
 *
 * @author Daniel DeGroff
 */
public class PublicKeyUse {
  public static String ENCRYPTION = "enc";

  public static String SIGNATURE = "sig";
}
