/*
 * Copyright (c) 2020-2025, FusionAuth, All Rights Reserved
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

package io.fusionauth;

import com.sun.net.httpserver.HttpServer;
import io.fusionauth.http.BuilderHTTPHandler;
import io.fusionauth.http.HttpServerBuilder;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.testng.ITestResult;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeSuite;

import java.security.Security;
import java.util.ArrayList;
import java.util.List;

/**
 * @author Daniel DeGroff
 */
public abstract class BaseTest {
  public static boolean FipsEnabled;

  public List<BuilderHTTPHandler> httpHandlers = new ArrayList<>();

  public List<HttpServer> httpServers = new ArrayList<>();

  @BeforeSuite
  public void beforeSuite() {
    FipsEnabled = Boolean.getBoolean("test.fips");
    if (FipsEnabled) {
      System.setProperty("org.bouncycastle.fips.approved_only", "true");
      Security.insertProviderAt(new BouncyCastleFipsProvider(), 1);
    }

    System.out.printf("Testing in %s mode with security provider [%s]%n",
        FipsEnabled ? "FIPS" : "the default JCA",
        Security.getProviders()[0].getClass().getCanonicalName());
  }

  @AfterMethod
  public void afterMethod(ITestResult result) {
    for (HttpServer httpServer : httpServers) {
      try {
        httpServer.stop(0);
      } catch (Exception ignore) {
      }
    }
  }

  protected void startHttpServer(ThrowingConsumer<HttpServerBuilder> consumer) throws Exception {
    HttpServerBuilder builder = new HttpServerBuilder();
    consumer.accept(builder);
    startHttpServer(builder);
  }

  public void startHttpServer(HttpServerBuilder builder) {
    httpServers.add(builder.build());
    httpHandlers.add(builder.handler);
  }

  public interface ThrowingConsumer<T> {
    void accept(T t) throws Exception;
  }
}

