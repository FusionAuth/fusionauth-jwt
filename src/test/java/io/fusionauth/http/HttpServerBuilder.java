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

package io.fusionauth.http;

import com.sun.net.httpserver.HttpServer;
import io.fusionauth.domain.Buildable;

import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Daniel DeGroff
 */
public class HttpServerBuilder implements Buildable<HttpServerBuilder> {
  public BuilderHTTPHandler handler;

  public int port;

  public Map<String, ExpectedResponse> responses = new HashMap<>();

  public HttpServer server;

  public HttpServer build() {
    if (port == 0) {
      throw new IllegalStateException("You forgot to set the port.");
    }

    for (ExpectedResponse result : responses.values()) {
      if (result.responseFile != null) {
        try {
          result.response = new String(Files.readAllBytes(result.responseFile.toAbsolutePath()));
        } catch (Exception e) {
          throw new RuntimeException(e);
        }
      }
    }

    try {
      InetSocketAddress addr = new InetSocketAddress(port);
      server = HttpServer.create(addr, 0);
      handler = new BuilderHTTPHandler(responses);
      server.createContext("/", handler);
      server.start();
      return server;
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public ExpectedResponseBuilder handleURI(String uri) {
    return new ExpectedResponseBuilder(this, uri);
  }

  public HttpServerBuilder listenOn(int port) {
    this.port = port;
    return this;
  }
}