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

import java.util.function.Supplier;

import org.shredzone.acme4j.Session;

import com.google.common.base.Preconditions;

// @formatter:off
public class SessionSupplier implements Supplier<Session> {
  private final String url;
  private Session session;

  public SessionSupplier(String url) {
    this.url = url;
    this.session = null;
  }

  @Override
  public Session get() {
    if (session == null) {
     session = new Session(url);
    }
    return Preconditions.checkNotNull(session, "Could not create session");
  }

}
