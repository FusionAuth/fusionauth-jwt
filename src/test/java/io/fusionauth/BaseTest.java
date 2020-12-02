package io.fusionauth;

import com.sun.net.httpserver.HttpServer;
import io.fusionauth.http.BuilderHTTPHandler;
import io.fusionauth.http.HttpServerBuilder;
import org.testng.ITestResult;
import org.testng.annotations.AfterMethod;

import java.util.ArrayList;
import java.util.List;

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

