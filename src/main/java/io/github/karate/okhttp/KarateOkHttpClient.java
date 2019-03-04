/**
 * MIT License
 *
 * Copyright (c) 2018 Gavin Nicol
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package io.github.karate.okhttp;

import static com.intuit.karate.http.Cookie.DOMAIN;
import static com.intuit.karate.http.Cookie.EXPIRES;
import static com.intuit.karate.http.Cookie.HTTP_ONLY;
import static com.intuit.karate.http.Cookie.PATH;
import static com.intuit.karate.http.Cookie.SECURE;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.intuit.karate.Config;
import com.intuit.karate.core.ScenarioContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.intuit.karate.ScriptValueMap;
import com.intuit.karate.http.Cookie;
import com.intuit.karate.http.HttpClient;
import com.intuit.karate.http.HttpResponse;
import com.intuit.karate.http.HttpUtils;
import com.intuit.karate.http.MultiPartItem;
import com.intuit.karate.http.MultiValuedMap;

import okhttp3.Call;
import okhttp3.CookieJar;
import okhttp3.FormBody;
import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.logging.HttpLoggingInterceptor;
import okhttp3.logging.HttpLoggingInterceptor.Level;
import se.akerfeldt.okhttp.signpost.OkHttpOAuthConsumer;
import se.akerfeldt.okhttp.signpost.SigningInterceptor;

/**
 * Karate OkHttp3 Client with integrated OAuth1 signing support
 */
public class KarateOkHttpClient extends HttpClient<RequestBody> {
    private class OkHttp3CookieJar implements CookieJar {
        public Map<HttpUrl, List<okhttp3.Cookie>> cookies()
        {
            return store;
        }

        @Override
        public List<okhttp3.Cookie> loadForRequest(final HttpUrl url)
        {
            final List<okhttp3.Cookie> cookies = store.get(url);
            return cookies != null ? cookies : new ArrayList<>();
        }

        @Override
        public void saveFromResponse(final HttpUrl url, final List<okhttp3.Cookie> cookies)
        {
            store.put(url, cookies);
        }

        private final Map<HttpUrl, List<okhttp3.Cookie>> store = new HashMap<>();
    }

    @Override
    public void configure(final Config config, final ScenarioContext context)
    {
        LOGGER.info("configure({},{})", config.getUserDefined(), context);
    }

    private OkHttpClient buildClient(final ScenarioContext context)
    {
        final Config config = context.getConfig();
        final ScriptValueMap vars = context.vars;
        final HttpLoggingInterceptor logger = new HttpLoggingInterceptor();
        final OkHttpClient.Builder builder = new OkHttpClient.Builder();

        // Turn on request logging if needed
        if (config.isShowLog()) {
            final String level = String.valueOf(buildValue(vars, "httpLogLevel", String.class, "BASIC")).toUpperCase();
            LOGGER.info("level : {}", level);
            logger.setLevel(Level.valueOf(level));
            builder.addInterceptor(logger);
        }

        // Configure SSL
        if (config.isSslEnabled()) {
            LOGGER.info("ssl({})", config.getSslAlgorithm());

            final String algorithm = config.getSslAlgorithm();
            final KeyStore trustStore =
                HttpUtils.getKeyStore(context, config.getSslTrustStore(), config.getSslTrustStorePassword(), config.getSslTrustStoreType());
            final KeyStore keyStore =
                HttpUtils.getKeyStore(context, config.getSslKeyStore(), config.getSslKeyStorePassword(), config.getSslKeyStoreType());
            // TODO: SSL config
            // clientBuilder.connectionSpecs(Arrays.asList(ConnectionSpec.MODERN_TLS,
            // ConnectionSpec.COMPATIBLE_TLS));
            // clientBuilder.sslSocketFactory(sslContext.getSocketFactory(),trustManager);
        }

        // OAuth
        if (buildValue(vars, "oauthSigning", Boolean.class, false)) {
            final String consumerKey = buildValue(vars, "oauthConsumerKey", String.class, "");
            final String consumerSecret = buildValue(vars, "oauthConsumerSecret", String.class, "");
            final String oauthToken = buildValue(vars, "oauthToken", String.class, "");
            final String oauthTokenSecret = buildValue(vars, "oauthTokenSecret", String.class, "");

            LOGGER.info("oauth(,'{}','{}','{}','{}')", consumerKey, consumerSecret, oauthToken, oauthTokenSecret);

            final OkHttpOAuthConsumer consumer = new OkHttpOAuthConsumer(consumerKey, consumerSecret);
            consumer.setTokenWithSecret(oauthToken, oauthTokenSecret);

            builder.addInterceptor(new SigningInterceptor(consumer));
            builder.addInterceptor(chain -> {
                System.out.println("-->" + chain.request().headers());
                return chain.proceed(chain.request());
            });
        }

        return builder.build();
    }

    private Request buildRequest(final RequestBody entity)
    {
        final Request.Builder builder = new Request.Builder();

        builder.method(request.getMethod(), entity);
        builder.url(buildUrl());
        LOGGER.info("buildRequest({})", request.getParams());
        return builder.build();
    }

    private HttpUrl buildUrl()
    {
        final HttpUrl.Builder builder = new HttpUrl.Builder();
        final URI uri = URI.create(request.getUrlAndPath());

        builder.scheme(uri.getScheme());
        builder.host(uri.getHost());
        builder.fragment(uri.getFragment());
        builder.addPathSegments(uri.getPath().substring(1));

        if (uri.getPort() > 0) {
            builder.port(uri.getPort());
        }

        if (request.getParams() != null) {
            request.getParams().forEach((name, values) -> {
                for (final Object o : values) {
                    System.out.println(String.valueOf(o));
                    builder.addQueryParameter(name, String.valueOf(o));
                }
            });
        }

        return builder.build();
    }

    private <T> T buildValue(final ScriptValueMap values, final String name, final Class<T> clazz, final T value)
    {
        if (values.containsKey(name)) {
            return values.get(name, clazz);
        }
        return value;
    }

    @Override
    protected void buildCookie(final Cookie cookie)
    {
        LOGGER.info("buildCookie({})", cookie);
    }

    @Override
    protected void buildHeader(final String name, final Object value, final boolean replace)
    {
        LOGGER.info("buildHeader({},{},{})", name, value, replace);
    }

    @Override
    protected void buildParam(final String name, final Object... values)
    {
        LOGGER.info("buildParam({},{})", name, values);
    }

    @Override
    protected void buildPath(final String path)
    {
        LOGGER.info("buildPath({})", path);
    }

    @Override
    protected void buildUrl(final String url)
    {
        LOGGER.info("buildUrl({})", url);
    }

    @Override
    protected RequestBody getEntity(final InputStream stream, final String type)
    {
        LOGGER.info("getEntity({},{})", stream, type);
        final MediaType contentType = MediaType.get(type);
        try (final ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
            int read;
            final byte[] data = new byte[1024];
            while ((read = stream.read(data, 0, data.length)) != -1) {
                buffer.write(data, 0, read);
            }
            buffer.flush();
            return RequestBody.create(contentType, buffer.toByteArray());
        }
        catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected RequestBody getEntity(final List<MultiPartItem> multiPartItems, final String mediaType)
    {
        LOGGER.info("getEntity({},{})", multiPartItems, mediaType);
        return null;
    }

    @Override
    protected RequestBody getEntity(final MultiValuedMap fields, final String type)
    {
        LOGGER.info("getEntity({},{})", fields, type);
        final FormBody.Builder builder = new FormBody.Builder();

        fields.forEach((k, l) -> {
            for (final Object o : l) {
                builder.add(k, String.valueOf(o));
            }
        });

        return builder.build();
    }

    @Override
    protected RequestBody getEntity(final String content, final String type)
    {
        LOGGER.info("getEntity({},{})", content, type);
        final MediaType contentType = MediaType.get(type);
        return RequestBody.create(contentType, content);
    }

    @Override
    protected String getRequestUri()
    {
        LOGGER.info("getRequestUri() -> {}", request.getUrl());
        return request.getUrl();
    }

    @Override
    protected HttpResponse makeHttpRequest(final RequestBody entity, final ScenarioContext context)
    {
        LOGGER.info("makeHttpRequest({},{})", entity, context);
        try {
            final OkHttp3CookieJar cookies = new OkHttp3CookieJar();
            final OkHttpClient client = buildClient(context);
            final Call call = client.newCall(buildRequest(entity));

            LOGGER.info("call: {}", call);

            final long startTime = System.currentTimeMillis();
            final Response resp = call.execute();
            final long endTime = System.currentTimeMillis();
            final HttpResponse response = new HttpResponse(startTime, endTime);
            final byte[] bytes = resp.body().bytes();
            response.setUri(getRequestUri());
            response.setBody(bytes);
            response.setStatus(resp.code());
            for (final HttpUrl u : cookies.cookies().keySet()) {
                for (final okhttp3.Cookie c : cookies.cookies().get(u)) {
                    final com.intuit.karate.http.Cookie cookie = new com.intuit.karate.http.Cookie(c.name(), c.value());
                    cookie.put(DOMAIN, u.host());
                    cookie.put(PATH, u.encodedPath());
                    cookie.put(EXPIRES, String.valueOf(c.expiresAt()));
                    cookie.put(SECURE, String.valueOf(c.secure()));
                    cookie.put(HTTP_ONLY, String.valueOf(c.httpOnly()));
                    // cookie.put(MAX_AGE, String.valueOf(c.expiresAt()));
                    response.addCookie(cookie);
                }
            }
            resp.headers().toMultimap().forEach((k, v) -> response.putHeader(k, v));
            return response;
        }
        catch (final Exception e) {
            LOGGER.warn("Error: {}", e.getMessage(), e);
            throw new RuntimeException(e);
        }
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(KarateOkHttpClient.class);
}
