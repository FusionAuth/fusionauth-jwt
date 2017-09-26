package org.primeframework.jwt;

import org.testng.Assert;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * @author Daniel DeGroff
 */
public abstract class BaseTest {
  protected String readFile(String fileName) {
    try {
      return new String(Files.readAllBytes(Paths.get("src/test/resources/" + fileName)));
    } catch (IOException e) {
      Assert.fail("Unexpected file I/O exception.", e);
      return null;
    }
  }
}
