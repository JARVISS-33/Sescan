package com.secscan;

import java.net.InetAddress;
import java.net.URI;

/**
 * Safety check: stops people using this server to scan private/internal addresses
 * (this attack is called SSRF). Only public http/https sites are allowed.
 */
public final class UrlGuard {
    private UrlGuard() {}

    public static URI check(String raw) {
        try {
            URI u = URI.create(raw.trim());
            String scheme = u.getScheme();
            if (scheme == null || !(scheme.equals("http") || scheme.equals("https"))) {
                throw new IllegalArgumentException("Only http:// or https:// URLs are allowed");
            }
            if (u.getHost() == null) throw new IllegalArgumentException("URL has no host name");
            for (InetAddress a : InetAddress.getAllByName(u.getHost())) {
                if (a.isAnyLocalAddress() || a.isLoopbackAddress() || a.isSiteLocalAddress()
                        || a.isLinkLocalAddress() || a.isMulticastAddress()) {
                    throw new IllegalArgumentException("Private or local addresses cannot be scanned");
                }
            }
            return u;
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid or unreachable URL");
        }
    }
}
