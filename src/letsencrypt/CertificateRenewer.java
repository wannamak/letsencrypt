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
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeRetryAfterException;

import com.google.common.base.Preconditions;
import com.google.common.io.Files;

// @formatter:off
public class CertificateRenewer {
  private final Logger logger = Logger.getLogger(CertificateRenewer.class.getName());
  private final Account account;
  private final Proto.Config config;
  private final Proto.AccountConfig accountConfig;
  private final Proto.Domain domain;
  private final KeyLoader keyLoader;

  public CertificateRenewer(Account account, Proto.AccountConfig accountConfig,
      Proto.Config config, Proto.Domain domain, KeyLoader keyLoader) {
    this.account = account;
    this.accountConfig = accountConfig;
    this.config = config;
    this.domain = domain;
    this.keyLoader = keyLoader;
  }

  public void renew() throws AcmeException, IOException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {
    String domainName = domain.getServerName(0);

    Order order = account.newOrder()
        .domains(domain.getServerNameList())
        .create();
    logger.info("Using order " + order.getLocation());

    List<Authorization> authorizations = order.getAuthorizations();
    for (Authorization authorization : authorizations) {
      if (authorization.getStatus() == Status.VALID) {
        logger.info("Authorization " + authorization.getLocation() + " is already VALID");
        continue;
      }
      processAuthorization(authorization, domain);
    }

    order.execute(keyLoader.loadCertificateSigningRequest(domainName));

    awaitOrderCompletion(order);

    Certificate certificate = order.getCertificate();
    writeRenewedCertificate(certificate, domainName);
  }

  private void processAuthorization(Authorization authorization, Proto.Domain domain) throws IOException, AcmeException {
    logger.info("Processing authorization " + authorization.getLocation()
        + " with status " + authorization.getStatus());
    Http01Challenge challenge = authorization.findChallenge(Http01Challenge.class);
    Preconditions.checkNotNull(challenge, "authorization does not have a HTTP challenge: "
        + authorization.getJSON().toString());
    awaitChallengeCompletion(authorization, challenge, domain.getWebRootDirectory());
  }

  private void awaitChallengeCompletion(Authorization authorization, Http01Challenge challenge,
      String webRootDirectory) throws IOException, AcmeException {
    File tempDir = new File(webRootDirectory, config.getAcmeDirectoryPrefix());
    Preconditions.checkState(tempDir.isDirectory(), "Expected an existing directory");
    File tempFile = new File(tempDir, challenge.getToken());
    Files.write(challenge.getAuthorization(), tempFile, StandardCharsets.UTF_8);
    logger.info("Wrote challenge file: " + tempFile.getAbsolutePath());

    try {
      challenge.trigger();
      awaitCompletion(() -> {
        authorization.update();
        return authorization.getStatus() == Status.VALID
            || authorization.getStatus() == Status.INVALID;
      });
    } finally {
      tempFile.delete();
    }

    Preconditions.checkState(authorization.getStatus() == Status.VALID,
        "Expected valid authorization but got " + authorization.getJSON().toString());

    logger.info("Authorization is now valid.");
  }

  private void awaitOrderCompletion(Order order) throws AcmeException {
    awaitCompletion(() -> {
      order.update();
      return order.getStatus() == Status.VALID
          || order.getStatus() == Status.INVALID;
      });

    Preconditions.checkState(order.getStatus() == Status.VALID,
        "Expected valid order but got " + order.getJSON().toString());

    logger.info("Order is valid.");
  }
  private static final int MAX_COUNT = 100;

  private void awaitCompletion(Callable<Boolean> work) throws AcmeException {
    int count = 0;
    final long originalSleepMillis = Duration.ofSeconds(config.getPollSleepDurationSeconds()).toMillis();
    long sleepMillis = originalSleepMillis;
    boolean isCompleted = false;
    do {
      try {
        Thread.sleep(sleepMillis);
      } catch (InterruptedException e) {
        logger.log(Level.INFO, "Sleep error", e);
      }
      try {
        isCompleted = work.call();
        sleepMillis = originalSleepMillis;
      } catch (AcmeRetryAfterException e) {
        Instant nextRetry = e.getRetryAfter();
        logger.info("Server advised a next retry at " + nextRetry);
        sleepMillis = nextRetry.toEpochMilli() - Instant.now().toEpochMilli();
        Preconditions.checkState(sleepMillis >= 0);
      } catch (AcmeException e) {
        throw e;
      } catch (Exception e) {
        throw new IllegalStateException(e);
      }
    } while (count++ < MAX_COUNT && !isCompleted);
    Preconditions.checkState(isCompleted, "Loop count exceeded");
  }

  private void writeRenewedCertificate(Certificate certificate, String domainName) throws IOException {
    File outputCertificate = new File(accountConfig.getKeyDirectory(),
        String.format(accountConfig.getCertificateFilenameSpec(), domainName));
    try (FileWriter writer = new FileWriter(outputCertificate)) {
      logger.info("Writing renewed certificate to " + outputCertificate.getAbsolutePath());
      certificate.writeCertificate(writer);
    }
  }
}
