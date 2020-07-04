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

import org.testng.IAnnotationTransformer;
import org.testng.annotations.ITestAnnotation;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.Signature;

/**
 * Test NG transformer used to disable tests at runtime.
 *
 * @author Daniel DeGroff
 */
@SuppressWarnings("unused")
public class TestNGAnnotationTransformer implements IAnnotationTransformer {
  private static boolean RSAProbabilisticSignatureSchemaAvailable;

  static {
    try {
      Signature.getInstance("RSASSA-PSS");
      RSAProbabilisticSignatureSchemaAvailable = true;
    } catch (Exception ignore) {
    }
  }

  @Override
  public void transform(ITestAnnotation annotation, Class testClass, Constructor testConstructor, Method testMethod) {
    RequiresAlgorithm requiresAlgorithm = testMethod.getAnnotation(RequiresAlgorithm.class);
    if (requiresAlgorithm != null) {
      // Only run these tests if the RSASSA PSS algorithm is available
      if (requiresAlgorithm.value().equals("RSASSA-PSS")) {
        annotation.setEnabled(RSAProbabilisticSignatureSchemaAvailable);
      }
    }
  }
}