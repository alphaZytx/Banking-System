package banking.ui.flow;

import banking.api.BankHttpServer;
import banking.security.AuthenticationException;
import banking.security.AuthenticationService;
import banking.security.AuthenticationToken;
import banking.security.TokenService;
import banking.ui.console.ConsoleIO;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Collection;

/**
 * Coordinates secure API server lifecycle and token operations.
 */
public class ApiServerFlow {
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("uuuu-MM-dd HH:mm:ss")
        .withZone(ZoneId.systemDefault());

    private final ConsoleIO io;
    private final AuthenticationService authenticationService;
    private final TokenService tokenService;
    private final BankHttpServer server;

    public ApiServerFlow(ConsoleIO io, AuthenticationService authenticationService,
                         TokenService tokenService, BankHttpServer server) {
        this.io = io;
        this.authenticationService = authenticationService;
        this.tokenService = tokenService;
        this.server = server;
    }

    public void manage() {
        boolean back = false;
        while (!back) {
            io.heading("API Security & Tokens");
            if (!server.isRunning()) {
                io.info("1. Launch secure API server");
                io.info("2. Back to main menu");
                int choice = io.promptInt("Select an option: ");
                switch (choice) {
                    case 1 -> startServer();
                    case 2 -> back = true;
                    default -> io.error("Invalid option.");
                }
            } else {
                io.info("1. Issue additional access token");
                io.info("2. List active tokens");
                io.info("3. Revoke token");
                io.info("4. Stop API server");
                io.info("5. Back to main menu");
                int choice = io.promptInt("Select an option: ");
                switch (choice) {
                    case 1 -> issueToken();
                    case 2 -> listTokens();
                    case 3 -> revokeToken();
                    case 4 -> stopServer();
                    case 5 -> back = true;
                    default -> io.error("Invalid option.");
                }
            }
        }
    }

    private void startServer() {
        AuthenticationToken token = authenticateOperator();
        if (token == null) {
            return;
        }
        server.start();
        io.success("Bank API started on port " + server.getPort());
        io.info("Use the following bearer token for API calls (Authorization: Bearer <token>):");
        io.println(token.token());
    }

    private void issueToken() {
        AuthenticationToken token = authenticateOperator();
        if (token == null) {
            return;
        }
        io.success("Issued token for " + token.principal());
        io.println(token.token());
    }

    private void listTokens() {
        Collection<AuthenticationToken> tokens = tokenService.activeTokens();
        if (tokens.isEmpty()) {
            io.warning("No active tokens.");
            return;
        }
        io.subHeading("Active Tokens");
        tokens.forEach(token -> io.println(
            token.principal() + " | expires " + FORMATTER.format(token.expiresAt()) +
                " | " + token.token()
        ));
    }

    private void revokeToken() {
        String tokenValue = io.prompt("Token to revoke: ");
        tokenService.revoke(tokenValue);
        io.success("Token revoked (if it existed).");
    }

    private void stopServer() {
        server.stop();
        io.success("API server stopped.");
    }

    private AuthenticationToken authenticateOperator() {
        String username = io.prompt("Operator username: ");
        String password = io.prompt("Operator password: ");
        try {
            return authenticationService.login(username, password);
        } catch (AuthenticationException e) {
            io.error(e.getMessage());
            return null;
        }
    }

    public void shutdown() {
        if (server.isRunning()) {
            server.stop();
        }
    }
}
