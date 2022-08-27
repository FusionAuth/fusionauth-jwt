/*
 * Copyright (c) 2020-2022, FusionAuth, All Rights Reserved
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

import java.util.ArrayList;
import java.util.List;

import com.sun.net.httpserver.HttpServer;
import io.fusionauth.http.BuilderHTTPHandler;
import io.fusionauth.http.HttpServerBuilder;
import io.fusionauth.jwt.domain.Algorithm;
import org.testng.ITestResult;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;

/**
 * @author Daniel DeGroff
 */
public abstract class BaseTest {
  public List<BuilderHTTPHandler> httpHandlers = new ArrayList<>();

  public List<HttpServer> httpServers = new ArrayList<>();

  @AfterMethod
  public void afterMethod(ITestResult result) {
    for (HttpServer httpServer : httpServers) {
      try {
        httpServer.stop(0);
      } catch (Exception ignore) {
      }
    }
  }

  @BeforeMethod
  public void beforeMethod() {
    // Reset the default configuration which is w/out the 'none' algorithm.
    Algorithm.deRegister(Algorithm.none);
  }

  public void startHttpServer(HttpServerBuilder builder) {
    httpServers.add(builder.build());
    httpHandlers.add(builder.handler);
  }

  protected void startHttpServer(ThrowingConsumer<HttpServerBuilder> consumer) throws Exception {
    HttpServerBuilder builder = new HttpServerBuilder();
    consumer.accept(builder);
    startHttpServer(builder);
  }

  public interface ThrowingConsumer<T> {
    void accept(T t) throws Exception;
  }
}

