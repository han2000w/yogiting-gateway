package com.yogiting.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;


@Slf4j
@Component
public class JwtAuthFilter extends AbstractGatewayFilterFactory<JwtAuthFilter.Config> {

    private static final AntPathMatcher pathMatcher = new AntPathMatcher();

    @Value("${jwt.secretKey}")
    private String secretKey;
    String userId = null;

    private static final Map<String, List<HttpMethod>> EXCLUDE_PATHS = Map.ofEntries(
            // 인증
            Map.entry("/v1/auth/login", List.of(HttpMethod.POST)),
            Map.entry("/v1/auth/signup", List.of(HttpMethod.POST)),
            Map.entry("/v1/auth/google/login", List.of(HttpMethod.POST)),
            Map.entry("/v1/auth/refreshToken", List.of(HttpMethod.POST)),
            // 게시글
            Map.entry("/v1/api/post/get", List.of(HttpMethod.GET)),
            Map.entry("/v1/api/post/get/*", List.of(HttpMethod.GET)),
            Map.entry("/v1/api/post/liked", List.of(HttpMethod.GET)),
            Map.entry("/v1/api/post/comment", List.of(HttpMethod.GET)),
            // 포인트샵
            Map.entry("/v1/api/shop", List.of(HttpMethod.GET)),
            // 채팅
            Map.entry("/v1/api/chat/room", List.of(HttpMethod.GET)),
            Map.entry("/v1/api/chat/ws/**", List.of(HttpMethod.GET))
    );

    private boolean isExcludedPath(String path, HttpMethod method) {
        return EXCLUDE_PATHS.entrySet().stream().anyMatch(entry ->
                pathMatcher.match(entry.getKey(), path) && entry.getValue().contains(method)
        );
    }

    public JwtAuthFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {

        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();

            String path = request.getURI().getPath();
            HttpMethod method = request.getMethod();

            String token = request.getHeaders().getFirst("Authorization");

            // 제외 경로 확인
            if (isExcludedPath(path, method)) {
                log.info("인증 제외 경로: {}", method, path);
                return chain.filter(exchange);
            }

            try {
                validToken(token);

                ServerHttpRequest mutatedRequest = request.mutate()
                        .header("X-User-Id", userId)
                        .build();

                return chain.filter(exchange.mutate().request(mutatedRequest).build());
            } catch (Exception e) {
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                response.getHeaders().add("Content-Type", "application/json");

                String jsonResponse = "{\"error\":\"UNAUTHORIZED\",\"message\":\"" + e.getMessage() + "\"}";
                DataBuffer buffer = response.bufferFactory().wrap(jsonResponse.getBytes(StandardCharsets.UTF_8));

                return response.writeWith(Mono.just(buffer));
            }


        };
    }

    public void validToken(String token) {

        if (token == null) {
            throw new IllegalArgumentException("JWT_TOKEN_NULL");
        } else if (!token.substring(0, 7).equals("Bearer ")) {
            throw new IllegalArgumentException("NOT_BEARER_TYPE");
        }

        String jwtToken = token.substring(7);

        // 토큰이 유효한지 확인
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(jwtToken)
                .getBody();

        this.userId = claims.getSubject();
    }

    public static class Config {
        private String baseMessage;
    }
}
