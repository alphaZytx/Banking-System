package banking.api;

import banking.persistence.BankDAO;
import banking.security.AuthorizationService;
import banking.security.TokenService;
import banking.service.Bank;

public final class ApiApplication {
    private static final int DEFAULT_PORT = 8080;

    private ApiApplication() {
    }

    public static void main(String[] args) {
        Bank bank = BankDAO.loadBank();
        int port = resolvePort();
        TokenService tokenService = new TokenService();
        AuthorizationService authorizationService = new AuthorizationService();
        BankHttpServer server = new BankHttpServer(bank, port, tokenService, authorizationService);
        Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
        server.start();
    }

    private static int resolvePort() {
        String override = System.getenv("BANKING_API_PORT");
        if (override == null || override.isBlank()) {
            return DEFAULT_PORT;
        }
        try {
            return Integer.parseInt(override.trim());
        } catch (NumberFormatException ex) {
            return DEFAULT_PORT;
        }
    }
}
