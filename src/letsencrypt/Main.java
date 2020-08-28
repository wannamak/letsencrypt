/**
 * Copyright 2020 Keith Wannamaker
 *
 * This file is part of letsencrypt-client.
 *
 * letsencrypt-client is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * letsencrypt-client is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with letsencrypt-client.  If not, see <http://www.gnu.org/licenses/>.
 */

package letsencrypt;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.OffsetDateTime;
import java.time.Period;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.Session;

import com.google.common.io.Files;
import com.google.protobuf.TextFormat;
import com.google.protobuf.TextFormat.ParseException;

// @formatter:off
public class Main {
  private final Logger logger = Logger.getLogger(Main.class.getName());
  private final Proto.Config config;
  private boolean restartRequired;

  public static void main(String args[]) throws Exception {
    new Main(args).run();
  }

  public Main(String args[]) throws ParseException, IOException {
    if (args.length != 1) {
      System.err.println("client.sh path-to-config-proto-txt-file");
      System.exit(-1);
    }
    config = readConfig(args[0]);
  }

  public void run() throws Exception {
    try {
      Supplier<Session> sessionSupplier = new SessionSupplier(config.getSessionUrl());
      for (Proto.AccountConfig accountConfig : config.getAccountConfigList()) {
        KeyLoader keyLoader = new KeyLoader(accountConfig);
        Supplier<Account> accountSupplier = new AccountSupplier(accountConfig, sessionSupplier);
        process(accountSupplier, accountConfig, keyLoader);
      }
      if (restartRequired) {
        Files.write(new byte[0], new File(config.getRestartNotificationFilename()));
      }
    } catch (Throwable t) {
      logger.log(Level.SEVERE, "Aborting", t);
      throw t;
    }
  }

  public void process(Supplier<Account> accountSupplier, Proto.AccountConfig accountConfig,
      KeyLoader keyLoader) throws Exception {
    for (Proto.Domain domain : accountConfig.getDomainList()) {
      Set<X509Certificate> certificates = keyLoader.loadCertificate(domain.getServerName(0));
      if (certificates == null
          || isExpiringWithin(Period.ofDays(accountConfig.getBufferPeriodDays()), certificates, domain)) {
        new CertificateRenewer(accountSupplier.get(), accountConfig, config, domain, keyLoader).renew();
        restartRequired = true;
      }
    }
  }

  private boolean isExpiringWithin(Period grace, Set<X509Certificate> certificates, Proto.Domain domain) {
    OffsetDateTime now = OffsetDateTime.now();
    OffsetDateTime nowPlusGrace = now.plus(grace);
    OffsetDateTime earliestExpiration = null;
    for (X509Certificate certificate : certificates) {
      OffsetDateTime expiration = certificate.getNotAfter().toInstant().atOffset(ZoneOffset.UTC);
      if (earliestExpiration == null
          || expiration.isBefore(earliestExpiration)) {
        earliestExpiration = expiration;
      }
      if (!nowPlusGrace.isBefore(expiration)) {
        logger.info(domain.getServerName(0) + " has or will expire at " + expiration);
        return true;
      }
    }
    logger.info(domain.getServerName(0) + " expires in "
        + now.until(earliestExpiration, ChronoUnit.DAYS) + " days");
    return false;
  }

  private Proto.Config readConfig(String filename) throws ParseException, IOException {
    Proto.Config.Builder config = Proto.Config.newBuilder();
    TextFormat.getParser().merge(
        Files.toString(new File(filename), StandardCharsets.UTF_8), config);
    return config.build();
  }
}
