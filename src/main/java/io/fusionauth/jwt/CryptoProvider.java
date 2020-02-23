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

package io.fusionauth.jwt;

import javax.crypto.Mac;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;

/**
 * @author Daniel DeGroff
 */
public class CryptoProvider {
  private static final boolean USE_BC_FIPS;

  private CryptoProvider() {
  }

  public static Mac getMacInstance(String name) throws NoSuchAlgorithmException {
    return USE_BC_FIPS ? getBCFipsMacInstance(name) : Mac.getInstance(name);
  }

  public static Signature getSignatureInstance(String name) throws NoSuchAlgorithmException {
    return USE_BC_FIPS ? getBCFipsSignatureInstance(name) : Signature.getInstance(name);
  }

  private static Mac getBCFipsMacInstance(String name) throws NoSuchAlgorithmException {
    try {
      return Mac.getInstance(name, "BCFIPS");
    } catch (NoSuchProviderException e) {
      // Should not happen since we checked during static initialization
      throw new RuntimeException(e);
    }
  }

  private static Signature getBCFipsSignatureInstance(String name) throws NoSuchAlgorithmException {
    try {
      return Signature.getInstance(name, "BCFIPS");
    } catch (NoSuchProviderException e) {
      // Should not happen since we checked during static initialization
      throw new RuntimeException(e);
    }
  }

  static {
    Signature signature = null;
    try {
      signature = Signature.getInstance("SHA256withRSA", "BCFIPS");
    } catch (Exception e) {
      if (!(e instanceof NoSuchProviderException)) {
        throw new RuntimeException(e);
      }
    }

    USE_BC_FIPS = signature != null;
  }
}
