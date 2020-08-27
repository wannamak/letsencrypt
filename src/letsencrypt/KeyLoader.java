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
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collection;
import java.util.Set;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import com.google.common.base.Preconditions;
import com.google.common.io.Files;

// @formatter:off
public class KeyLoader {
  private final Logger logger = Logger.getLogger(KeyLoader.class.getName());
  private final Proto.AccountConfig accountConfig;

  public KeyLoader(Proto.AccountConfig accountConfig) {
    this.accountConfig = accountConfig;
  }

  public KeyPair loadAccountKey() throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, IOException  {
    KeyFactory kf = KeyFactory.getInstance("RSA");
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(loadPem(
        new File(accountConfig.getKeyDirectory(), accountConfig.getAccountPrivateKeyFilename()))));
    PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(loadPem(
        new File(accountConfig.getKeyDirectory(), accountConfig.getAccountPublicKeyFilename()))));
    return new KeyPair(publicKey, privateKey);
  }

  public byte[] loadCertificateSigningRequest(String domainName) throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, IOException  {
    File file = new File(accountConfig.getKeyDirectory(),
        String.format(accountConfig.getCertificateSigningRequestFilenameSpec(), domainName));
    logger.info("Reading CSR from " + file.getAbsolutePath());
    return loadPem(file);
  }

  public Set<X509Certificate> loadCertificate(String domainName) throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, IOException  {
    File file = new File(accountConfig.getKeyDirectory(),
        String.format(accountConfig.getCertificateFilenameSpec(), domainName));
    CertificateFactory factory = CertificateFactory.getInstance("X.509");
    logger.info("Reading certificate from " + file.getAbsolutePath());
    Collection<? extends Certificate> certificates = factory.generateCertificates(
        new FileInputStream(file));
    return certificates
        .stream()
        .map(c -> (X509Certificate) c)
        .collect(Collectors.toSet());
  }

  private static final Pattern PEM_PATTERN = Pattern.compile(
      "(?m)(?s)^---*BEGIN.*---*$(.*)^---*END.*---*$.*");

  private byte[] loadPem(File pemFile) throws IOException {
    logger.info("Reading key from " + pemFile.getAbsolutePath());
    String key = Files.toString(pemFile, StandardCharsets.UTF_8);
    Matcher matcher = PEM_PATTERN.matcher(key);
    Preconditions.checkState(matcher.matches());
    return Base64.getMimeDecoder().decode(matcher.group(1));
  }
}
