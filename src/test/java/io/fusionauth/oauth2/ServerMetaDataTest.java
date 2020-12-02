package io.fusionauth.oauth2;

import io.fusionauth.BaseTest;
import io.fusionauth.http.ExpectedResponse;
import io.fusionauth.oauth2.domain.AuthorizationServerMetaData;
import org.testng.annotations.Test;

import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Paths;

import static org.testng.Assert.assertEquals;

/**
 * @author Daniel DeGroff
 */
public class ServerMetaDataTest extends BaseTest {
  @Test
  public void test() throws Exception {
    // Start a server to return server meta data.
    startHttpServer(server -> server
        .listenOn(4242)
        .handleURI("/.well-known/oauth-authorization-server")
        .andReturn(new ExpectedResponse()
            .with(response -> response.responseFile = Paths.get("src/test/resources/oauth2/example_server_metadata.json"))
            .with(response -> response.contentType = "application/json")
            .with(response -> response.status = 200)));

    AuthorizationServerMetaData metaData1 = ServerMetaDataHelper.retrieveFromIssuer("http://localhost:4242");
    AuthorizationServerMetaData metaData2 = ServerMetaDataHelper.retrieveFromWellKnownConfiguration("http://localhost:4242/.well-known/oauth-authorization-server");
    AuthorizationServerMetaData metaData3 = ServerMetaDataHelper.retrieveFromWellKnownConfiguration((HttpURLConnection) new URL("http://localhost:4242/.well-known/oauth-authorization-server").openConnection());

    assertEquals(metaData1, metaData2);
    assertEquals(metaData2, metaData3);
  }
}
