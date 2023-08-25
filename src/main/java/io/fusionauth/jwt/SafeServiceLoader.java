package io.fusionauth.jwt;

import java.util.HashSet;
import java.util.ServiceLoader;
import java.util.Set;

/**
 * A service loader that will detect duplicates and explode.
 *
 * @author Daniel DeGroff
 */
public class SafeServiceLoader {
  public static <S> ServiceLoader<S> load(Class<S> service) {
    ServiceLoader<S> loader = ServiceLoader.load(service);
    Set<S> set = new HashSet<>();
    for (S s : loader) {
      if (set.contains(s)) {
        throw new IllegalStateException("A duplicate provider was detected when loading [" + service.getSimpleName() + "].");
      }

      set.add(s);
    }

    return loader;
  }
}
