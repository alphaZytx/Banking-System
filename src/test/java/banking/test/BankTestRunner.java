package banking.test;

import banking.account.Account;
import banking.api.BankHttpServer;
import banking.persistence.memory.InMemoryAccountRepository;
import banking.security.AuthorizationService;
import banking.security.TokenService;
import banking.service.Bank;
import banking.operation.OperationResult;

import java.net.HttpURLConnection;
import java.net.URL;
import java.time.Duration;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

/**
 * Lightweight smoke test harness that exercises the core domain flows and the HTTP facade.
 */
public final class BankTestRunner {
    public static void main(String[] args) throws Exception {
        BankTestRunner runner = new BankTestRunner();
        runner.shouldDepositFunds();
        runner.shouldWithdrawFunds();
        runner.shouldTransferFunds();
        runner.shouldStartHttpServer();
        System.out.println("All smoke tests passed.");
    }

    private void shouldDepositFunds() {
        Bank bank = new Bank(new InMemoryAccountRepository());
        try {
            Account account = bank.createAccount("Alice", "savings", 0);
            CompletableFuture<OperationResult> future = bank.deposit(account.getAccountNumber(), 150);
            OperationResult result = future.join();
            assertTrue(result.isSuccess(), "Deposit should succeed");
            assertEquals(150.0, bank.getAccount(account.getAccountNumber()).getBalance(), 0.0001);
        } finally {
            bank.shutdown();
        }
    }

    private void shouldWithdrawFunds() {
        Bank bank = new Bank(new InMemoryAccountRepository());
        try {
            Account account = bank.createAccount("Bob", "savings", 0);
            bank.deposit(account.getAccountNumber(), 200).join();
            OperationResult result = bank.withdraw(account.getAccountNumber(), 75).join();
            assertTrue(result.isSuccess(), "Withdrawal should succeed");
            assertEquals(125.0, bank.getAccount(account.getAccountNumber()).getBalance(), 0.0001);
        } finally {
            bank.shutdown();
        }
    }

    private void shouldTransferFunds() {
        Bank bank = new Bank(new InMemoryAccountRepository());
        try {
            Account source = bank.createAccount("Carol", "savings", 0);
            Account target = bank.createAccount("Dave", "current", 0);
            bank.deposit(source.getAccountNumber(), 300).join();
            OperationResult result = bank.transfer(source.getAccountNumber(), target.getAccountNumber(), 120).join();
            assertTrue(result.isSuccess(), "Transfer should succeed");
            assertEquals(180.0, bank.getAccount(source.getAccountNumber()).getBalance(), 0.0001);
            assertEquals(120.0, bank.getAccount(target.getAccountNumber()).getBalance(), 0.0001);
        } finally {
            bank.shutdown();
        }
    }

    private void shouldStartHttpServer() throws Exception {
        Bank bank = new Bank(new InMemoryAccountRepository());
        TokenService tokenService = new TokenService();
        AuthorizationService authorizationService = new AuthorizationService();
        BankHttpServer server = new BankHttpServer(bank, 0, tokenService, authorizationService);
        server.start();
        try {
            int port = server.getPort();
            URL url = new URL("http://localhost:" + port + "/health");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestProperty("Authorization", "Bearer " + issueToken(tokenService));
            connection.connect();
            int status = connection.getResponseCode();
            assertEquals(200, status, "Health endpoint should respond with 200");
        } finally {
            server.stop();
            bank.shutdown();
        }
    }

    private String issueToken(TokenService tokenService) {
        return tokenService.issueToken("test", java.util.Set.of(banking.security.Role.AUDITOR), Duration.ofMinutes(5)).token();
    }

    private void assertEquals(double expected, double actual, double delta) {
        if (Math.abs(expected - actual) > delta) {
            throw new AssertionError("Expected " + expected + " but was " + actual);
        }
    }

    private void assertEquals(int expected, int actual, String message) {
        if (expected != actual) {
            throw new AssertionError(message + " (expected " + expected + " but was " + actual + ")");
        }
    }

    private void assertTrue(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
