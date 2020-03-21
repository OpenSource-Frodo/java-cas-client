/**
 * Licensed to Apereo under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Apereo licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.jasig.cas.client.authentication;

import java.io.IOException;
import org.jasig.cas.client.util.CommonUtils;
import reactor.core.CoreSubscriber;
import reactor.core.publisher.Mono;
import reactor.core.publisher.ParallelFlux;
import reactor.netty.http.server.HttpServerRequest;
import reactor.netty.http.server.HttpServerResponse;

/**
 * Implementation of the redirect strategy that can handle a Faces Ajax request in addition to the standard redirect style.
 *
 * @author Scott Battaglia
 * @since 3.3.0
 */
public final class FacesCompatibleAuthenticationRedirectStrategy implements AuthenticationRedirectStrategy {

    private static final String FACES_PARTIAL_AJAX_PARAMETER = "javax.faces.partial.ajax";
    @Override
    public Mono<Void> redirect(HttpServerRequest request, HttpServerResponse response, String potentialRedirectUrl) throws IOException {
        if (CommonUtils.isNotBlank(request.param(FACES_PARTIAL_AJAX_PARAMETER))) {
            // this is an ajax request - redirect ajaxly
            response.header("ContentType","text/xml");
            response.status(200);

            response.sendString(new ParallelFlux<String>() {
                @Override
                public int parallelism() {
                    return 0;
                }

                @Override
                protected void subscribe(CoreSubscriber<? super String>[] coreSubscribers) {
                    coreSubscribers[0].onNext("<?xml version='1.0' encoding='UTF-8'?>");
                    coreSubscribers[0].onNext(String.format("<partial-response><redirect url=\"%s\"></redirect></partial-response>",
                            potentialRedirectUrl));
                    coreSubscribers[0].onComplete();
                }
            });
        } else {
           return response.sendRedirect(potentialRedirectUrl);
        }
    }
}
