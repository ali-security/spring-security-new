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

package org.springframework.security.web.server.firewall;

import java.net.URI;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link StrictServerWebExchangeFirewall}.
 *
 * @author Rob Winch
 * @since 6.4
 */
public class StrictServerWebExchangeFirewallTests {

	public String[] unnormalizedPaths = { "http://exploit.example/..", "http://exploit.example/./path/",
			"http://exploit.example/path/path/.", "http://exploit.example/path/path//.",
			"http://exploit.example/./path/../path//.", "http://exploit.example/./path",
			"http://exploit.example/.//path", "http://exploit.example/.", "http://exploit.example//path",
			"http://exploit.example//path/path", "http://exploit.example//path//path",
			"http://exploit.example/path//path" };

	private StrictServerWebExchangeFirewall firewall = new StrictServerWebExchangeFirewall();

	private MockServerHttpRequest.BaseBuilder<?> request = get("/");

	@Test
	public void cookieWhenHasNewLineThenThrowsException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> ResponseCookie.from("test","Something\nhere").build());
	}

	@Test
	public void cookieWhenHasLineFeedThenThrowsException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> ResponseCookie.from("test","Something\rhere").build());
	}

	@Test
	public void responseHeadersWhenValueHasNewLineThenThrowsException() {
		this.request = MockServerHttpRequest.get("/");
		ServerWebExchange exchange = getFirewalledExchange();
		exchange.getResponse().getHeaders().set("FOO", "new\nline");
		assertThatIllegalArgumentException().isThrownBy(() -> exchange.getResponse().setComplete().block());
	}

	@Test
	public void responseHeadersWhenValueHasLineFeedThenThrowsException() {
		this.request = MockServerHttpRequest.get("/");
		ServerWebExchange exchange = getFirewalledExchange();
		exchange.getResponse().getHeaders().set("FOO", "line\rfeed");
		assertThatIllegalArgumentException().isThrownBy(() -> exchange.getResponse().setComplete().block());
	}

	@Test
	public void responseHeadersWhenNameHasNewLineThenThrowsException() {
		this.request = MockServerHttpRequest.get("/");
		ServerWebExchange exchange = getFirewalledExchange();
		exchange.getResponse().getHeaders().set("new\nline", "FOO");
		assertThatIllegalArgumentException().isThrownBy(() -> exchange.getResponse().setComplete().block());
	}

	@Test
	public void responseHeadersWhenNameHasLineFeedThenThrowsException() {
		this.request = MockServerHttpRequest.get("/");
		ServerWebExchange exchange = getFirewalledExchange();
		exchange.getResponse().getHeaders().set("line\rfeed", "FOO");
		assertThatIllegalArgumentException().isThrownBy(() -> exchange.getResponse().setComplete().block());
	}

	// Skipped: HttpMethod is an enum in Spring 5.x — valueOf("INVALID") throws
	// IllegalArgumentException before reaching the firewall. This path is tested
	// in Spring 6.x where HttpMethod accepts arbitrary strings.

	private ServerWebExchange getFirewalledExchange() {
		MockServerWebExchange exchange = MockServerWebExchange.from(this.request.build());
		return this.firewall.getFirewalledExchange(exchange).block();
	}

	private MockServerHttpRequest.BodyBuilder get(String uri) {
		URI url = URI.create(uri);
		return MockServerHttpRequest.method(HttpMethod.GET, url);
	}

	// blocks XST attacks
	@Test
	public void getFirewalledExchangeWhenTraceMethodThenThrowsServerExchangeRejectedException() {
		this.request = MockServerHttpRequest.method(HttpMethod.TRACE, "/");
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> getFirewalledExchange());
	}

	@Test
	// blocks XST attack if request is forwarded to a Microsoft IIS web server
	public void getFirewalledExchangeWhenTrackMethodThenThrowsServerExchangeRejectedException() {
		this.request = MockServerHttpRequest.method(HttpMethod.TRACE, "/");
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> getFirewalledExchange());
	}

	// Skipped: HttpMethod.valueOf("get") throws IllegalArgumentException in Spring 5.x
	// because HttpMethod is an enum. Case-sensitive method validation is tested in Spring 6.x.

	@Test
	public void getFirewalledExchangeWhenAllowedThenNoException() {
		List<String> allowedMethods = Arrays.asList("DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT");
		for (String allowedMethod : allowedMethods) {
			this.request = MockServerHttpRequest.method(HttpMethod.valueOf(allowedMethod), "/");
			getFirewalledExchange();
		}
	}

	// Skipped: HttpMethod.valueOf("INVALID") throws IllegalArgumentException in Spring 5.x.

	@Test
	public void getFirewalledExchangeWhenURINotNormalizedThenThrowsServerExchangeRejectedException() {
		for (String path : this.unnormalizedPaths) {
			this.request = get(path);
			assertThatExceptionOfType(ServerExchangeRejectedException.class)
				.describedAs("The path '" + path + "' is not normalized")
				.isThrownBy(() -> getFirewalledExchange());
		}
	}

	@Test
	public void getFirewalledExchangeWhenSemicolonInRequestUriThenThrowsServerExchangeRejectedException() {
		this.request = get("/path;/");
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> getFirewalledExchange());
	}

	@Test
	public void getFirewalledExchangeWhenEncodedSemicolonInRequestUriThenThrowsServerExchangeRejectedException() {
		this.request = get("/path%3B/");
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> getFirewalledExchange());
	}

	@Test
	public void getFirewalledExchangeWhenLowercaseEncodedSemicolonInRequestUriThenThrowsServerExchangeRejectedException() {
		this.request = MockServerHttpRequest.method(HttpMethod.GET, URI.create("/path%3b/"));
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> getFirewalledExchange());
	}

	@Test
	public void getFirewalledExchangeWhenSemicolonInRequestUriAndAllowSemicolonThenNoException() {
		this.firewall.setAllowSemicolon(true);
		this.request = get("/path;/");
		getFirewalledExchange();
	}

	@Test
	public void getFirewalledExchangeWhenEncodedSemicolonInRequestUriAndAllowSemicolonThenNoException() {
		this.firewall.setAllowSemicolon(true);
		this.request = get("/path%3B/");
		getFirewalledExchange();
	}

	@Test
	public void getFirewalledExchangeWhenLowercaseEncodedSemicolonInRequestUriAndAllowSemicolonThenNoException() {
		this.firewall.setAllowSemicolon(true);
		this.request = get("/path%3b/");
		getFirewalledExchange();
	}

	@Test
	public void getFirewalledExchangeWhenLowercaseEncodedPeriodInThenThrowsServerExchangeRejectedException() {
		this.request = get("/%2e/");
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> getFirewalledExchange());
	}

	@Test
	public void getFirewalledExchangeWhenContainsLowerboundAsciiThenNoException() {
		this.request = get("/%20");
		getFirewalledExchange();
	}

	@Test
	public void getFirewalledExchangeWhenContainsUpperboundAsciiThenNoException() {
		this.request = get("/~");
		getFirewalledExchange();
	}

	@Test
	public void getFirewalledExchangeWhenJapaneseCharacterThenNoException() {
		// FIXME: .method(HttpMethod.GET to .get and similar methods
		this.request = get("/\u3042");
		getFirewalledExchange();
	}

	@Test
	public void getFirewalledExchangeWhenContainsEncodedNullThenException() {
		this.request = get("/something%00/");
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> getFirewalledExchange());
	}

	@Test
	public void getFirewalledExchangeWhenContainsLowercaseEncodedLineFeedThenException() {
		this.request = get("/something%0a/");
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> getFirewalledExchange());
	}

	@Test
	public void getFirewalledExchangeWhenContainsUppercaseEncodedLineFeedThenException() {
		this.request = get("/something%0A/");
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> getFirewalledExchange());
	}

	@Test
	public void getFirewalledExchangeWhenContainsLowercaseEncodedCarriageReturnThenException() {
		this.request = get("/something%0d/");
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> getFirewalledExchange());
	}

	@Test
	public void getFirewalledExchangeWhenContainsUppercaseEncodedCarriageReturnThenException() {
		this.request = get("/something%0D/");
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> getFirewalledExchange());
	}

	@Test
	public void getFirewalledExchangeWhenContainsLowercaseEncodedLineFeedAndAllowedThenNoException() {
		this.firewall.setAllowUrlEncodedLineFeed(true);
		this.request = get("/something%0a/");
		getFirewalledExchange();
	}

	@Test
	public void getFirewalledExchangeWhenContainsUppercaseEncodedLineFeedAndAllowedThenNoException() {
		this.firewall.setAllowUrlEncodedLineFeed(true);
		this.request = get("/something%0A/");
		getFirewalledExchange();
	}

	@Test
	public void getFirewalledExchangeWhenContainsLowercaseEncodedCarriageReturnAndAllowedThenNoException() {
		this.firewall.setAllowUrlEncodedCarriageReturn(true);
		this.request = get("/something%0d/");
		getFirewalledExchange();
	}

	@Test
	public void getFirewalledExchangeWhenContainsUppercaseEncodedCarriageReturnAndAllowedThenNoException() {
		this.firewall.setAllowUrlEncodedCarriageReturn(true);
		this.request = get("/something%0D/");
		getFirewalledExchange();
	}

	/**
	 * On WebSphere 8.5 a URL like /context-root/a/b;%2f1/c can bypass a rule on /a/b/c
	 * because the pathInfo is /a/b;/1/c which ends up being /a/b/1/c while Spring MVC
	 * will strip the ; content from requestURI before the path is URL decoded.
	 */
	@Test
	public void getFirewalledExchangeWhenLowercaseEncodedPathThenException() {
		this.request = get("/context-root/a/b;%2f1/c");
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> getFirewalledExchange());
	}

	@Test
	public void getFirewalledExchangeWhenUppercaseEncodedPathThenException() {
		this.request = get("/context-root/a/b;%2F1/c");
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> getFirewalledExchange());
	}

	@Test
	public void getFirewalledExchangeWhenAllowUrlEncodedSlashAndLowercaseEncodedPathThenNoException() {
		this.firewall.setAllowUrlEncodedSlash(true);
		this.firewall.setAllowSemicolon(true);
		this.request = get("/context-root/a/b;%2f1/c");
		getFirewalledExchange();
	}

	@Test
	public void getFirewalledExchangeWhenAllowUrlEncodedSlashAndUppercaseEncodedPathThenNoException() {
		this.firewall.setAllowUrlEncodedSlash(true);
		this.firewall.setAllowSemicolon(true);
		this.request = get("/context-root/a/b;%2F1/c");
		getFirewalledExchange();
	}

	@Test
	public void getFirewalledExchangeWhenAllowUrlLowerCaseEncodedDoubleSlashThenNoException() {
		this.firewall.setAllowUrlEncodedSlash(true);
		this.firewall.setAllowUrlEncodedDoubleSlash(true);
		this.request = get("/context-root/a/b%2f%2fc");
		getFirewalledExchange();
	}

	@Test
	public void getFirewalledExchangeWhenAllowUrlUpperCaseEncodedDoubleSlashThenNoException() {
		this.firewall.setAllowUrlEncodedSlash(true);
		this.firewall.setAllowUrlEncodedDoubleSlash(true);
		this.request = get("/context-root/a/b%2F%2Fc");
		getFirewalledExchange();
	}

	@Test
	public void getFirewalledExchangeWhenAllowUrlLowerCaseAndUpperCaseEncodedDoubleSlashThenNoException() {
		this.firewall.setAllowUrlEncodedSlash(true);
		this.firewall.setAllowUrlEncodedDoubleSlash(true);
		this.request = get("/context-root/a/b%2f%2Fc");
		getFirewalledExchange();
	}

	@Test
	public void getFirewalledExchangeWhenAllowUrlUpperCaseAndLowerCaseEncodedDoubleSlashThenNoException() {
		this.firewall.setAllowUrlEncodedSlash(true);
		this.firewall.setAllowUrlEncodedDoubleSlash(true);
		this.request = get("/context-root/a/b%2F%2fc");
		getFirewalledExchange();
	}

	@Test
	public void getFirewalledExchangeWhenRemoveFromUpperCaseEncodedUrlBlocklistThenNoException() {
		this.firewall.setAllowUrlEncodedSlash(true);
		this.request = get("/context-root/a/b%2Fc");
		this.firewall.getEncodedUrlBlocklist().removeAll(Arrays.asList("%2F%2F"));
		getFirewalledExchange();
	}

	@Test
	public void getFirewalledExchangeWhenRemoveFromDecodedUrlBlocklistThenNoException() {
		this.request = get("/a/b%2F%2Fc");
		this.firewall.getDecodedUrlBlocklist().removeAll(Arrays.asList("//"));
		this.firewall.getEncodedUrlBlocklist().removeAll(Arrays.asList("%2F%2F"));
		this.firewall.getEncodedUrlBlocklist().removeAll(Arrays.asList("%2F"));
		getFirewalledExchange();
	}

	@Test
	public void getFirewalledExchangeWhenTrustedDomainThenNoException() {
		this.request.header("Host", "example.org");
		this.firewall.setAllowedHostnames((hostname) -> hostname.equals("example.org"));
		getFirewalledExchange();
	}

	@Test
	public void getFirewalledExchangeWhenUntrustedDomainThenException() {
		this.request = get("https://example.org");
		this.firewall.setAllowedHostnames((hostname) -> hostname.equals("myexample.org"));
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> getFirewalledExchange());
	}

	@Test
	public void getFirewalledExchangeGetHeaderWhenNotAllowedHeaderNameThenException() {
		this.firewall.setAllowedHeaderNames((name) -> !name.equals("bad name"));
		ServerWebExchange exchange = getFirewalledExchange();
		HttpHeaders headers = exchange.getRequest().getHeaders();
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> headers.get("bad name"));
	}

	@Test
	public void getFirewalledExchangeWhenHeaderNameNotAllowedWithAugmentedHeaderNamesThenException() {
		this.firewall.setAllowedHeaderNames(
				StrictServerWebExchangeFirewall.ALLOWED_HEADER_NAMES.and((name) -> !name.equals("bad name")));
		ServerWebExchange exchange = getFirewalledExchange();
		HttpHeaders headers = exchange.getRequest().getHeaders();
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> headers.getFirst("bad name"));
	}

	@Test
	public void getFirewalledExchangeGetHeaderWhenNotAllowedHeaderValueThenException() {
		this.request.header("good name", "bad value");
		this.firewall.setAllowedHeaderValues((value) -> !value.equals("bad value"));
		ServerWebExchange exchange = getFirewalledExchange();
		HttpHeaders headers = exchange.getRequest().getHeaders();
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> headers.get("good name"));
	}

	@Test
	public void getFirewalledExchangeWhenHeaderValueNotAllowedWithAugmentedHeaderValuesThenException() {
		this.request.header("good name", "bad value");
		this.firewall.setAllowedHeaderValues(
				StrictServerWebExchangeFirewall.ALLOWED_HEADER_VALUES.and((value) -> !value.equals("bad value")));
		ServerWebExchange exchange = getFirewalledExchange();
		HttpHeaders headers = exchange.getRequest().getHeaders();
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> headers.get("good name"));
	}

	@Test
	public void getFirewalledExchangeGetDateHeaderWhenControlCharacterInHeaderNameThenException() {
		this.request.header("Bad\0Name", "some value");
		ServerWebExchange exchange = getFirewalledExchange();
		HttpHeaders headers = exchange.getRequest().getHeaders();
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> headers.get("Bad\0Name"));
	}

	@Test
	public void getFirewalledExchangeGetHeaderWhenUndefinedCharacterInHeaderNameThenException() {
		this.request.header("Bad\uFFFEName", "some value");
		ServerWebExchange exchange = getFirewalledExchange();
		HttpHeaders headers = exchange.getRequest().getHeaders();
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> headers.get("Bad\uFFFEName"));
	}

	@Test
	public void getFirewalledExchangeGetHeadersWhenControlCharacterInHeaderNameThenException() {
		this.request.header("Bad\0Name", "some value");
		ServerWebExchange exchange = getFirewalledExchange();
		HttpHeaders headers = exchange.getRequest().getHeaders();
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> headers.get("Bad\0Name"));
	}

	@Test
	public void getFirewalledExchangeGetHeaderNamesWhenControlCharacterInHeaderNameThenException() {
		this.request.header("Bad\0Name", "some value");
		ServerWebExchange exchange = getFirewalledExchange();
		HttpHeaders headers = exchange.getRequest().getHeaders();
		assertThatExceptionOfType(ServerExchangeRejectedException.class)
			.isThrownBy(() -> headers.keySet().iterator().next());
	}

	@Test
	public void getFirewalledExchangeGetHeaderWhenControlCharacterInHeaderValueThenException() {
		this.request.header("Something", "bad\0value");
		ServerWebExchange exchange = getFirewalledExchange();
		HttpHeaders headers = exchange.getRequest().getHeaders();
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> headers.get("Something"));
	}

	@Test
	public void getFirewalledExchangeGetHeaderWhenHorizontalTabInHeaderValueThenNoException() {
		this.request.header("Something", "tab\tvalue");
		ServerWebExchange exchange = getFirewalledExchange();
		HttpHeaders headers = exchange.getRequest().getHeaders();
		assertThat(headers.getFirst("Something")).isEqualTo("tab\tvalue");
	}

	@Test
	public void getFirewalledExchangeGetHeaderWhenUndefinedCharacterInHeaderValueThenException() {
		this.request.header("Something", "bad\uFFFEvalue");
		ServerWebExchange exchange = getFirewalledExchange();
		HttpHeaders headers = exchange.getRequest().getHeaders();
		assertThatExceptionOfType(ServerExchangeRejectedException.class)
			.isThrownBy(() -> headers.getFirst("Something"));
	}

	@Test
	public void getFirewalledExchangeGetHeadersWhenControlCharacterInHeaderValueThenException() {
		this.request.header("Something", "bad\0value");
		ServerWebExchange exchange = getFirewalledExchange();
		HttpHeaders headers = exchange.getRequest().getHeaders();
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> headers.get("Something"));
	}

	@Test
	public void getFirewalledExchangeGetParameterWhenControlCharacterInParameterNameThenException() {
		this.request.queryParam("Bad\0Name", "some value");
		ServerWebExchange exchange = getFirewalledExchange();
		ServerHttpRequest request = exchange.getRequest();
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(request::getQueryParams);
	}

	@Test
	public void getFirewalledExchangeGetParameterValuesWhenNotAllowedInParameterValueThenException() {
		this.firewall.setAllowedParameterValues((value) -> !value.equals("bad value"));
		this.request.queryParam("Something", "bad value");
		ServerWebExchange exchange = getFirewalledExchange();
		ServerHttpRequest request = exchange.getRequest();
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> request.getQueryParams());
	}

	@Test
	public void getFirewalledExchangeGetParameterValuesWhenNotAllowedInParameterNameThenException() {
		this.firewall.setAllowedParameterNames((value) -> !value.equals("bad name"));
		this.request.queryParam("bad name", "good value");
		ServerWebExchange exchange = getFirewalledExchange();
		ServerHttpRequest request = exchange.getRequest();
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> request.getQueryParams());
	}

	// gh-9598
	@Test
	public void getFirewalledExchangeGetHeaderWhenNameIsNullThenNull() {
		ServerWebExchange exchange = getFirewalledExchange();
		assertThat(exchange.getRequest().getHeaders().get(null)).isNull();
	}

}
