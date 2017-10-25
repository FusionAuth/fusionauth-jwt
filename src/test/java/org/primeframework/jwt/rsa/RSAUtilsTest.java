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

package org.primeframework.jwt.rsa;

import org.testng.annotations.Test;

import java.nio.charset.Charset;
import java.util.Base64;

import static org.testng.Assert.assertEquals;

/**
 * @author Daniel DeGroff
 */
public class RSAUtilsTest {
  @Test
  public void jws_x5t() throws Exception {
    String encodedCertificate = "MIIC5jCCAc6gAwIBAgIQNCdDZLmeeL5H6O2BE+aQCjANBgkqhkiG9w0BAQsFADAvMS0wKwYDVQQDEyRBREZTIFNpZ25pbmcgLSB1bWdjb25uZWN0LnVtdXNpYy5jb20wHhcNMTcxMDE4MTUyOTAzWhcNMTgxMDE4MTUyOTAzWjAvMS0wKwYDVQQDEyRBREZTIFNpZ25pbmcgLSB1bWdjb25uZWN0LnVtdXNpYy5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDnUl7AwWO1fjpijswRY40bs8jegA4Kz4ycM12h8PqD0CbydWyCnPmY/mzI8EPWsaT3uJ4QaYEEq+taNTu/GB8eFDs1flDb1JNjkZ2ECDZpdwgAS/z+RvI7D+tRARNUU7QvkMAOfFTb3zS4Cx52RoXlp3Bdrtzk9KaO/DJc7IoxLCAWuXL8kxuBRwfPzeQXX/i+wIRtkJAFotOq7j/XxgYO0/UzCenZDAr+Xbl8JfmrkFaegEQFwAC2/jlAP9OYjF39qD+9kI/HP9CcnXxoAIbq8lJkIKvuoURV9mErlel2Oj+tgvveq28NEV36RwqnfAqAIsAT4BTs739JUsnoHnKbAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAGesHLA8V2/4ljxwbjeBsBBk8fJ4DGVufKJJXBit7jb37/9/XVtkVg1Y2IuVoYnzpnOxAZ/Zizp8/HKH2bApqEOcAU3oZ471FZlzXAv1G51S0i1UUD/OWgc3z84pk9AMtWSka26GOWA4pb/Mw/nrBrG3R8NY6ZgLZQqbYR2GQBj5JXbDsJtzYkVXY6N5KmsBekVJ92ddjKMy5SfcGY0j3BFFsBOUpaONWgBFAD2rOH9FnwoY7tcTKa5u4MfwSXMYLal/Vk9kFAtBV2Uqe/MgitB8OgAGYYqGU8VRPVH4K/n8sx5EarZPXcOJkHbI/C70Puc0jxra4e4/2c4HqifMAYQ=";
    byte[] derEncodedCertificate = Base64.getDecoder().decode(encodedCertificate.getBytes(Charset.forName("UTF-8")));

    // Pass in Base64 encode certificate
    assertEquals(RSAUtils.generateJWS_x5t(encodedCertificate), "vDT213a_AF5eRdElKZla9-9dpc8");
    assertEquals(RSAUtils.generateJWS_x5t("SHA-1", encodedCertificate), "vDT213a_AF5eRdElKZla9-9dpc8");

    // Pass in DER encoded certificate
    assertEquals(RSAUtils.generateJWS_x5t(derEncodedCertificate), "vDT213a_AF5eRdElKZla9-9dpc8");
    assertEquals(RSAUtils.generateJWS_x5t("SHA-1", derEncodedCertificate), "vDT213a_AF5eRdElKZla9-9dpc8");

    // Base64 Encoded and DER Encoded using SHA-256
    assertEquals(RSAUtils.generateJWS_x5t("SHA-256", encodedCertificate), "tIFNLfPYY14sM0DLTp6T-BZ3yPaPUPKc8Hnh6evXTeM");
    assertEquals(RSAUtils.generateJWS_x5t("SHA-256", derEncodedCertificate), "tIFNLfPYY14sM0DLTp6T-BZ3yPaPUPKc8Hnh6evXTeM");
  }
}
