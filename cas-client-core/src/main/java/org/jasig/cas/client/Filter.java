package org.jasig.cas.client;

import reactor.netty.http.server.HttpServerRequest;
import reactor.netty.http.server.HttpServerResponse;

import java.io.IOException;

/**
 * @author: frodoking
 * @date: 2020/03/21
 * @description:
 */
public interface Filter {

    default void init(FilterConfig filterConfig) {
    }

    void doFilter(HttpServerRequest httpServerRequest, HttpServerResponse httpServerResponse) throws IOException;

    default void destroy() {
    }

    public static class FilterConfig {

    }

}
