/*
 * Copyright 2002-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.server;

import java.util.Arrays;
import java.util.List;

import org.junit.Test;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.web.server.firewall.ServerExchangeRejectedException;
import org.springframework.security.web.server.firewall.ServerExchangeRejectedHandler;
import org.springframework.security.web.server.firewall.ServerWebExchangeFirewall;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher.MatchResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class WebFilterChainProxyTests {

	// gh-4668
	@Test
	public void filterWhenNoMatchThenContinuesChainAnd404() {
		List<WebFilter> filters = Arrays.asList(new Http200WebFilter());
		ServerWebExchangeMatcher notMatch = (exchange) -> MatchResult.notMatch();
		MatcherSecurityWebFilterChain chain = new MatcherSecurityWebFilterChain(notMatch, filters);
		WebFilterChainProxy filter = new WebFilterChainProxy(chain);
		WebTestClient.bindToController(new Object()).webFilter(filter).build().get().exchange().expectStatus()
				.isNotFound();
	}

	@Test
	public void doFilterWhenFirewallRejectsThenBadRequest() {
		List<WebFilter> filters = Arrays.asList(new Http200WebFilter());
		ServerWebExchangeMatcher notMatch = (exchange) -> MatchResult.notMatch();
		MatcherSecurityWebFilterChain chain = new MatcherSecurityWebFilterChain(notMatch, filters);
		WebFilterChainProxy filter = new WebFilterChainProxy(chain);
		ServerWebExchangeFirewall firewall = mock(ServerWebExchangeFirewall.class);
		given(firewall.getFirewalledExchange(any()))
			.willReturn(Mono.error(new ServerExchangeRejectedException("Rejected")));
		filter.setFirewall(firewall);
		MockServerHttpRequest request = MockServerHttpRequest.get("/test").build();
		MockServerWebExchange exchange = MockServerWebExchange.from(request);
		filter.filter(exchange, (e) -> Mono.empty()).block();
		assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
	}

	@Test
	public void doFilterWhenCustomFirewallThenInvoked() {
		List<WebFilter> filters = Arrays.asList(new Http200WebFilter());
		ServerWebExchangeMatcher notMatch = (exchange) -> MatchResult.notMatch();
		MatcherSecurityWebFilterChain chain = new MatcherSecurityWebFilterChain(notMatch, filters);
		WebFilterChainProxy filter = new WebFilterChainProxy(chain);
		ServerExchangeRejectedHandler handler = mock(ServerExchangeRejectedHandler.class);
		ServerWebExchangeFirewall firewall = mock(ServerWebExchangeFirewall.class);
		filter.setFirewall(firewall);
		filter.setExchangeRejectedHandler(handler);
		WebTestClient.bindToController(new Object()).webFilter(filter).build().get().exchange();
		verify(firewall).getFirewalledExchange(any());
		verifyNoInteractions(handler);
	}

	@Test
	public void doFilterWhenCustomExchangeRejectedHandlerThenInvoked() {
		List<WebFilter> filters = Arrays.asList(new Http200WebFilter());
		ServerWebExchangeMatcher notMatch = (exchange) -> MatchResult.notMatch();
		MatcherSecurityWebFilterChain chain = new MatcherSecurityWebFilterChain(notMatch, filters);
		WebFilterChainProxy filter = new WebFilterChainProxy(chain);
		ServerExchangeRejectedHandler handler = mock(ServerExchangeRejectedHandler.class);
		ServerWebExchangeFirewall firewall = mock(ServerWebExchangeFirewall.class);
		given(firewall.getFirewalledExchange(any()))
			.willReturn(Mono.error(new ServerExchangeRejectedException("Oops")));
		filter.setFirewall(firewall);
		filter.setExchangeRejectedHandler(handler);
		WebTestClient.bindToController(new Object()).webFilter(filter).build().get().exchange();
		verify(firewall).getFirewalledExchange(any());
		verify(handler).handle(any(), any());
	}

	@Test
	public void doFilterWhenDelayedServerExchangeRejectedException() {
		List<WebFilter> filters = Arrays.asList(new WebFilter() {
			@Override
			public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
				return Mono.error(new ServerExchangeRejectedException("Ooops"));
			}
		});
		ServerWebExchangeMatcher match = (exchange) -> MatchResult.match();
		MatcherSecurityWebFilterChain chain = new MatcherSecurityWebFilterChain(match, filters);
		WebFilterChainProxy filter = new WebFilterChainProxy(chain);
		ServerExchangeRejectedHandler handler = mock(ServerExchangeRejectedHandler.class);
		filter.setExchangeRejectedHandler(handler);
		WebTestClient.bindToController(new Object())
			.webFilter(filter)
			.build()
			.get()
			.exchange();
		verify(handler).handle(any(), any());
	}

	static class Http200WebFilter implements WebFilter {

		@Override
		public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
			return Mono.fromRunnable(() -> exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN));
		}

	}

}
