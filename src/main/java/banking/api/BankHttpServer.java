package banking.api;

import banking.account.Account;
import banking.operation.OperationResult;
import banking.security.AuthorizationService;
import banking.security.Permission;
import banking.security.TokenService;
import banking.security.AuthenticationToken;
import banking.security.ForbiddenException;
import banking.security.UnauthorizedException;
import banking.service.Bank;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.StringJoiner;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Hardened HTTP facade exposing banking capabilities for automation and integration tests.
 */
public final class BankHttpServer {
    private static final Duration OPERATION_TIMEOUT = Duration.ofSeconds(10);
    private static final String APPLICATION_JSON = "application/json; charset=utf-8";
    private static final String AUTHORIZATION = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final Bank bank;
    private final int requestedPort;
    private final TokenService tokenService;
    private final AuthorizationService authorizationService;
    private HttpServer server;
    private ExecutorService executorService;

    public BankHttpServer(Bank bank, int port, TokenService tokenService,
                          AuthorizationService authorizationService) {
        this.bank = Objects.requireNonNull(bank, "bank");
        this.requestedPort = port;
        this.tokenService = Objects.requireNonNull(tokenService, "tokenService");
        this.authorizationService = Objects.requireNonNull(authorizationService, "authorizationService");
    }

    public synchronized void start() {
        if (server != null) {
            return;
        }
        try {
            server = HttpServer.create(new InetSocketAddress(requestedPort), 0);
        } catch (IOException e) {
            throw new IllegalStateException("Unable to start HTTP server", e);
        }
        executorService = Executors.newFixedThreadPool(Math.max(4, Runtime.getRuntime().availableProcessors()));
        server.setExecutor(executorService);

        register("/health", Permission.HEALTH_READ, this::handleHealth);
        register("/metrics", Permission.HEALTH_READ, this::handleMetrics);
        register("/accounts", Permission.ACCOUNT_READ, this::handleAccountsCollection);
        register("/accounts/", null, this::handleAccountDetail);
        register("/operations/deposit", Permission.FUNDS_DEPOSIT, this::handleDeposit);
        register("/operations/withdraw", Permission.FUNDS_WITHDRAW, this::handleWithdraw);
        register("/operations/transfer", Permission.FUNDS_TRANSFER, this::handleTransfer);

        server.start();
        System.out.printf(Locale.US, "HTTP API listening on port %d%n", getPort());
    }

    public synchronized void stop() {
        if (server != null) {
            server.stop(1);
            server = null;
        }
        if (executorService != null) {
            executorService.shutdown();
            try {
                if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                    executorService.shutdownNow();
                }
            } catch (InterruptedException e) {
                executorService.shutdownNow();
                Thread.currentThread().interrupt();
            } finally {
                executorService = null;
            }
        }
    }

    public synchronized boolean isRunning() {
        return server != null;
    }

    public synchronized int getPort() {
        if (server == null) {
            throw new IllegalStateException("Server is not running");
        }
        return server.getAddress().getPort();
    }

    private void register(String path, Permission permission, Handler handler) {
        server.createContext(path, exchange -> {
            try {
                AuthenticationToken token = authenticate(exchange, permission);
                handler.handle(exchange, token);
            } catch (UnauthorizedException e) {
                respond(exchange, 401, jsonError(e.getMessage()));
            } catch (ForbiddenException e) {
                respond(exchange, 403, jsonError(e.getMessage()));
            } catch (IllegalArgumentException e) {
                respond(exchange, 400, jsonError(e.getMessage()));
            } catch (Exception e) {
                respond(exchange, 500, jsonError("Internal server error: " + e.getMessage()));
            } finally {
                exchange.close();
            }
        });
    }

    private AuthenticationToken authenticate(HttpExchange exchange, Permission permission) {
        Headers headers = exchange.getRequestHeaders();
        String headerValue = headers.getFirst(AUTHORIZATION);
        if (headerValue == null || !headerValue.startsWith(BEARER_PREFIX)) {
            throw new UnauthorizedException("Missing or invalid Authorization header");
        }
        String tokenValue = headerValue.substring(BEARER_PREFIX.length()).trim();
        Optional<AuthenticationToken> maybeToken = tokenService.validate(tokenValue);
        AuthenticationToken token = maybeToken.orElseThrow(() -> new UnauthorizedException("Invalid or expired token"));
        if (permission != null) {
            authorizationService.ensureAuthorized(token, permission);
        }
        return token;
    }

    private void handleHealth(HttpExchange exchange, AuthenticationToken token) {
        if (!"GET".equals(exchange.getRequestMethod())) {
            respond(exchange, 405, jsonError("Method not allowed"));
            return;
        }
        respond(exchange, 200, "{\"status\":\"UP\"}");
    }

    private void handleMetrics(HttpExchange exchange, AuthenticationToken token) {
        if (!"GET".equals(exchange.getRequestMethod())) {
            respond(exchange, 405, jsonError("Method not allowed"));
            return;
        }
        int accounts = bank.getAllAccounts().size();
        int pending = bank.getPendingOperationCount();
        String body = String.format(Locale.US,
                "{\"accounts\":%d,\"pendingOperations\":%d}",
                accounts, pending);
        respond(exchange, 200, body);
    }

    private void handleAccountsCollection(HttpExchange exchange, AuthenticationToken token) {
        String method = exchange.getRequestMethod();
        if ("GET".equals(method)) {
            handleListAccounts(exchange);
        } else if ("POST".equals(method)) {
            authorizationService.ensureAuthorized(token, Permission.ACCOUNT_CREATE);
            Map<String, String> params = parseParams(exchange);
            String userName = require(params, "userName");
            String accountType = require(params, "accountType");
            double initialDeposit = parseAmount(params.get("initialDeposit"), 0.0);
            Account account = bank.createAccount(userName, accountType, initialDeposit);
            respond(exchange, 201, accountJson(account));
        } else {
            respond(exchange, 405, jsonError("Method not allowed"));
        }
    }

    private void handleAccountDetail(HttpExchange exchange, AuthenticationToken token) {
        URI uri = exchange.getRequestURI();
        String path = uri.getPath();
        if (!path.startsWith("/accounts/")) {
            respond(exchange, 404, jsonError("Not found"));
            return;
        }
        String idSegment = path.substring("/accounts/".length());
        if (idSegment.isBlank()) {
            respond(exchange, 404, jsonError("Account not specified"));
            return;
        }
        int accountNumber = parseAccountNumber(idSegment);
        String method = exchange.getRequestMethod();
        switch (method) {
            case "GET" -> {
                Account account = bank.getAccount(accountNumber);
                if (account == null) {
                    respond(exchange, 404, jsonError("Account not found"));
                } else {
                    respond(exchange, 200, accountJson(account));
                }
            }
            case "PUT" -> {
                authorizationService.ensureAuthorized(token, Permission.ACCOUNT_CREATE);
                Map<String, String> params = parseParams(exchange);
                String userName = params.get("userName");
                if (userName == null || userName.isBlank()) {
                    respond(exchange, 400, jsonError("userName is required"));
                    return;
                }
                boolean updated = bank.updateAccountHolderName(accountNumber, userName);
                if (!updated) {
                    respond(exchange, 404, jsonError("Account not found"));
                } else {
                    Account account = bank.getAccount(accountNumber);
                    respond(exchange, 200, accountJson(account));
                }
            }
            case "DELETE" -> {
                authorizationService.ensureAuthorized(token, Permission.ACCOUNT_CREATE);
                boolean closed = bank.closeAccount(accountNumber);
                if (!closed) {
                    respond(exchange, 404, jsonError("Account not found"));
                } else {
                    respond(exchange, 200, "{\"success\":true}");
                }
            }
            default -> respond(exchange, 405, jsonError("Method not allowed"));
        }
    }

    private void handleDeposit(HttpExchange exchange, AuthenticationToken token) throws Exception {
        ensureMethod(exchange, "POST");
        Map<String, String> params = parseParams(exchange);
        int accountNumber = parseAccountNumber(require(params, "accountNumber"));
        double amount = parseAmount(require(params, "amount"));
        OperationResult result = await(bank.deposit(accountNumber, amount));
        respond(exchange, statusFor(result), resultJson(result));
    }

    private void handleWithdraw(HttpExchange exchange, AuthenticationToken token) throws Exception {
        ensureMethod(exchange, "POST");
        Map<String, String> params = parseParams(exchange);
        int accountNumber = parseAccountNumber(require(params, "accountNumber"));
        double amount = parseAmount(require(params, "amount"));
        OperationResult result = await(bank.withdraw(accountNumber, amount));
        respond(exchange, statusFor(result), resultJson(result));
    }

    private void handleTransfer(HttpExchange exchange, AuthenticationToken token) throws Exception {
        ensureMethod(exchange, "POST");
        Map<String, String> params = parseParams(exchange);
        int source = parseAccountNumber(require(params, "sourceAccount"));
        int target = parseAccountNumber(require(params, "targetAccount"));
        double amount = parseAmount(require(params, "amount"));
        OperationResult result = await(bank.transfer(source, target, amount));
        respond(exchange, statusFor(result), resultJson(result));
    }

    private void handleListAccounts(HttpExchange exchange) {
        List<Account> accounts = bank.getAllAccounts();
        StringJoiner joiner = new StringJoiner(",", "{\"accounts\":[", "]}");
        for (Account account : accounts) {
            joiner.add(accountJson(account));
        }
        respond(exchange, 200, joiner.toString());
    }

    private void ensureMethod(HttpExchange exchange, String expected) {
        if (!expected.equals(exchange.getRequestMethod())) {
            throw new IllegalArgumentException("Method not allowed");
        }
    }

    private String accountJson(Account account) {
        return String.format(Locale.US,
                "{\"accountNumber\":%d,\"userName\":\"%s\",\"accountType\":\"%s\",\"balance\":%.2f}",
                account.getAccountNumber(),
                escape(account.getUserName()),
                escape(account.getAccountType()),
                account.getBalance());
    }

    private Map<String, String> parseParams(HttpExchange exchange) {
        if (exchange.getRequestMethod().equals("GET")) {
            return parseQuery(exchange.getRequestURI().getRawQuery());
        }
        String contentType = Optional.ofNullable(exchange.getRequestHeaders().getFirst("Content-Type"))
                .orElse("application/x-www-form-urlencoded");
        if (!contentType.contains("application/x-www-form-urlencoded")) {
            throw new IllegalArgumentException("Unsupported content type: " + contentType);
        }
        String body = readBody(exchange.getRequestBody());
        return parseQuery(body);
    }

    private Map<String, String> parseQuery(String query) {
        Map<String, String> params = new HashMap<>();
        if (query == null || query.isBlank()) {
            return params;
        }
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf('=');
            if (idx == -1) {
                continue;
            }
            String key = decode(pair.substring(0, idx));
            String value = decode(pair.substring(idx + 1));
            params.put(key, value);
        }
        return params;
    }

    private String decode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private String readBody(InputStream stream) {
        try {
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("Unable to read request body", e);
        }
    }

    private String require(Map<String, String> params, String key) {
        String value = params.get(key);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(key + " is required");
        }
        return value;
    }

    private int parseAccountNumber(String input) {
        try {
            return Integer.parseInt(input.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid account number: " + input);
        }
    }

    private double parseAmount(String input) {
        return parseAmount(input, Double.NaN);
    }

    private double parseAmount(String input, double defaultValue) {
        if (input == null || input.isBlank()) {
            if (Double.isNaN(defaultValue)) {
                throw new IllegalArgumentException("Amount is required");
            }
            return defaultValue;
        }
        try {
            double amount = Double.parseDouble(input.trim());
            if (Double.isNaN(defaultValue) && amount <= 0) {
                throw new IllegalArgumentException("Amount must be positive");
            }
            return amount;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid amount: " + input);
        }
    }

    private OperationResult await(CompletableFuture<OperationResult> future) throws Exception {
        try {
            return future.get(OPERATION_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            throw new IllegalStateException("Operation timed out", e);
        }
    }

    private int statusFor(OperationResult result) {
        return result.isSuccess() ? 200 : 422;
    }

    private String resultJson(OperationResult result) {
        return String.format(Locale.US,
                "{\"success\":%s,\"message\":\"%s\"}",
                result.isSuccess(),
                escape(result.getMessage()));
    }

    private String jsonError(String message) {
        return String.format(Locale.US, "{\"success\":false,\"error\":\"%s\"}", escape(message));
    }

    private void respond(HttpExchange exchange, int status, String body) {
        try {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            Headers headers = exchange.getResponseHeaders();
            headers.set("Content-Type", status >= 400 ? APPLICATION_JSON : APPLICATION_JSON);
            exchange.sendResponseHeaders(status, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        } catch (IOException e) {
            throw new IllegalStateException("Unable to write response", e);
        }
    }

    private String escape(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        for (char c : value.toCharArray()) {
            switch (c) {
                case '"' -> builder.append("\\\"");
                case '\\' -> builder.append("\\\\");
                case '\n' -> builder.append("\\n");
                case '\r' -> builder.append("\\r");
                case '\t' -> builder.append("\\t");
                default -> builder.append(c);
            }
        }
        return builder.toString();
    }

    @FunctionalInterface
    private interface Handler {
        void handle(HttpExchange exchange, AuthenticationToken token) throws Exception;
    }
}
