package org.owasp.dependencycheck.utils;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockserver.client.MockServerClient;
import org.mockserver.junit.MockServerRule;
import org.mockserver.matchers.Times;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;

public class HttpResourceConnectionIT extends BaseTest {
  @Rule
  public MockServerRule mockServerRule = new MockServerRule(this);

  private MockServerClient mockServerClient;

  @Before
  public void reset() {
    mockServerClient.reset();
  }


  @Test
  public void testGetHttpResource() throws IOException, TooManyRequestsException, ResourceNotFoundException {
    mockServerClient.when(HttpRequest.request().withMethod("GET").withPath("/insecure/file.txt"))
        .respond(HttpResponse.response().withBody("ok").withStatusCode(200));

    URL url = new URL("http://localhost:" + mockServerClient.remoteAddress().getPort() + "/insecure/file.txt");

    try (HttpResourceConnection resource = new HttpResourceConnection(getSettings())) {
      InputStream in = resource.fetch(url);
      byte[] read = new byte[2];
      in.read(read);
      String text = new String(read, UTF_8);
      assertEquals("ok", text);
    }
  }

  @Test
  public void testSecureGetHttpResource() throws IOException, TooManyRequestsException, ResourceNotFoundException {
    mockServerClient.when(HttpRequest.request().withMethod("GET").withPath("/secure/file.txt"), Times.once())
        .respond(HttpResponse.response().withStatusCode(401));
    mockServerClient.when(HttpRequest.request().withMethod("GET").withPath("/secure/file.txt"), Times.once())
        .respond(HttpResponse.response().withBody("ok").withStatusCode(200));

    URL url = new URL("http://username:password@localhost:" + mockServerClient.remoteAddress().getPort() + "/secure/file.txt");

    try (HttpResourceConnection resource = new HttpResourceConnection(getSettings())) {
      InputStream in = resource.fetch(url);
      byte[] read = new byte[2];
      in.read(read);
      String text = new String(read, UTF_8);
      assertEquals("ok", text);
    }
  }
}
