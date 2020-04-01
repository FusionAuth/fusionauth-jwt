/*
 * Copyright (c) 2020, FusionAuth, All Rights Reserved
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

package io.fusionauth.security;

import javax.crypto.Mac;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;

/**
 * The default Crypto Provider for FusionAuth JWT. This will utilize the default security provider to get
 * instances of MAC or signature algorithms.
 *
 * @author Daniel DeGroff
 */
public class DefaultCryptoProvider implements CryptoProvider {
  public Mac getMacInstance(String name) throws NoSuchAlgorithmException {
    return Mac.getInstance(name);
  }

  public Signature getSignatureInstance(String name) throws NoSuchAlgorithmException {
    return Signature.getInstance(name);
  }
}
