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
import java.security.NoSuchProviderException;
import java.security.Signature;

/**
 * This Crypto Provider utilizes the FIPS certified Bouncy Castle Security Provider (BCFIPS).
 * <p>
 * To utilize this provider, ensure you have the bc-fips jar in your classpath at runtime and have added the
 * BC Fips Security provider.
 * <p>
 * This library does not have a compile time or runtime dependency on the FIPS ready Bouncy Castle jar.
 * <p>
 * This implementation has been provided as an example, utilize it with the above usage warnings in mind or write
 * your own by implementing the <code>CryptoProvider</code> interface.
 *
 * @author Daniel DeGroff
 */
@SuppressWarnings("unused")
public class BCFIPSCryptoProvider implements CryptoProvider {
  public Mac getMacInstance(String name) throws NoSuchAlgorithmException {
    try {
      return Mac.getInstance(name, "BCFIPS");
    } catch (NoSuchProviderException e) {
      throw new RuntimeException(e);
    }
  }

  public Signature getSignatureInstance(String name) throws NoSuchAlgorithmException {
    try {
      return Signature.getInstance(name, "BCFIPS");
    } catch (NoSuchProviderException e) {
      throw new RuntimeException(e);
    }
  }
}
