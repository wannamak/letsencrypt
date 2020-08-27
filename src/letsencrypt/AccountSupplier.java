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

import java.net.URL;
import java.security.KeyPair;
import java.util.function.Supplier;
import java.util.logging.Logger;

import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Session;

import com.google.common.base.Preconditions;

public class AccountSupplier implements Supplier<Account> {
  private final Logger logger = Logger.getLogger(AccountSupplier.class.getName());
  private final Proto.AccountConfig accountConfig;
  private final Supplier<Session> sessionSupplier;
  private final KeyLoader keyLoader;
  private Account account;

  public AccountSupplier(Proto.AccountConfig accountConfig, Supplier<Session> sessionSupplier) {
    this.accountConfig = accountConfig;
    this.sessionSupplier = sessionSupplier;
    this.keyLoader = new KeyLoader(accountConfig);
  }

  @Override
  public Account get() {
    if (account == null) {
      try {
        account = loadAccount();
      } catch (Exception e) {
        throw new IllegalStateException(e);
      }
    }
    return Preconditions.checkNotNull(account);
  }

  private Account loadAccount() throws Exception {
    Session session = sessionSupplier.get();
    if (accountConfig.getAccountUrl().isEmpty()) {
      return createAccount(session, keyLoader, accountConfig);
    }
    KeyPair accountKeyPair = keyLoader.loadAccountKey();
    URL accountUrl = new URL(accountConfig.getAccountUrl());
    Login login = session.login(accountUrl, accountKeyPair);
    Account account = login.getAccount();
    logger.info("Returining existing account " + account.getLocation());
    return account;
  }

  public Account createAccount(Session session, KeyLoader keyLoader, Proto.AccountConfig accountConfig)
      throws Exception {
    KeyPair accountKeyPair = keyLoader.loadAccountKey();

    Account account = new AccountBuilder().addContact("mailto:" + accountConfig.getAccountEmail())
        .agreeToTermsOfService().useKeyPair(accountKeyPair).create(session);
    logger.info("Created account with URL " + account.getLocation());
    return account;
  }
}
