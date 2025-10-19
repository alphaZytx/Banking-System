package banking;

import banking.api.BankHttpServer;
import banking.persistence.AccountRepository;
import banking.persistence.memory.InMemoryAccountRepository;
import banking.persistence.jdbc.JdbcAccountRepository;
import banking.persistence.jdbc.JdbcConnectionProvider;
import banking.persistence.jdbc.MigrationRunner;
import banking.security.AuthenticationService;
import banking.security.AuthorizationService;
import banking.security.CredentialStore;
import banking.security.OperatorCredential;
import banking.security.PasswordHasher;
import banking.security.Role;
import banking.security.TokenService;
import banking.service.Bank;
import banking.ui.ConsoleUI;

import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.util.Properties;
import java.util.Set;

/**
 * Boots the interactive console experience.
 */
public final class BankingApplication {
    private static final int DEFAULT_API_PORT = 8080;

    private BankingApplication() {
    }

    public static void main(String[] args) {
        Properties properties = loadProperties();
        String persistence = resolve(properties, "banking.persistence", "BANKING_PERSISTENCE", "memory");
        AccountRepository repository = createRepository(persistence, properties);
        Bank bank = new Bank(repository);

        PasswordHasher hasher = new PasswordHasher();
        CredentialStore credentialStore = bootstrapCredentials(hasher, properties);
        TokenService tokenService = new TokenService();
        AuthorizationService authorizationService = new AuthorizationService();
        AuthenticationService authenticationService = new AuthenticationService(
                credentialStore, hasher, tokenService, Duration.ofHours(2));

        int apiPort = resolveApiPort(properties);
        BankHttpServer httpServer = new BankHttpServer(bank, apiPort, tokenService, authorizationService);

        ConsoleUI ui = new ConsoleUI(bank, authenticationService, tokenService, httpServer);
        ui.start();
    }

    private static CredentialStore bootstrapCredentials(PasswordHasher hasher, Properties properties) {
        CredentialStore store = new CredentialStore();
        String adminPassword = resolve(properties, "banking.credentials.admin", "BANKING_ADMIN_PASSWORD", "admin123!");
        String tellerPassword = resolve(properties, "banking.credentials.teller", "BANKING_TELLER_PASSWORD", "teller123!");
        String auditorPassword = resolve(properties, "banking.credentials.auditor", "BANKING_AUDITOR_PASSWORD", "auditor123!");
        store.store(new OperatorCredential("admin", hasher.hash(adminPassword), Set.of(Role.ADMIN)));
        store.store(new OperatorCredential("teller", hasher.hash(tellerPassword), Set.of(Role.TELLER)));
        store.store(new OperatorCredential("auditor", hasher.hash(auditorPassword), Set.of(Role.AUDITOR)));
        return store;
    }

    private static AccountRepository createRepository(String persistence, Properties properties) {
        if ("jdbc".equalsIgnoreCase(persistence)) {
            String url = resolve(properties, "banking.jdbc.url", "BANKING_JDBC_URL", null);
            if (url == null || url.isBlank()) {
                throw new IllegalStateException("banking.jdbc.url must be provided for JDBC persistence");
            }
            String username = resolve(properties, "banking.jdbc.username", "BANKING_JDBC_USERNAME", "");
            String password = resolve(properties, "banking.jdbc.password", "BANKING_JDBC_PASSWORD", "");
            String driver = resolve(properties, "banking.jdbc.driver", "BANKING_JDBC_DRIVER", "org.h2.Driver");
            try {
                Class.forName(driver);
            } catch (ClassNotFoundException e) {
                throw new IllegalStateException("Unable to load JDBC driver: " + driver, e);
            }
            JdbcConnectionProvider provider = new JdbcConnectionProvider(url, username, password);
            new MigrationRunner(provider, BankingApplication.class.getClassLoader()).runMigrations();
            return new JdbcAccountRepository(provider);
        }
        return new InMemoryAccountRepository();
    }

    private static int resolveApiPort(Properties properties) {
        String override = resolve(properties, "banking.api.port", "BANKING_API_PORT", null);
        if (override == null || override.isBlank()) {
            return DEFAULT_API_PORT;
        }
        try {
            return Integer.parseInt(override.trim());
        } catch (NumberFormatException ex) {
            return DEFAULT_API_PORT;
        }
    }

    private static Properties loadProperties() {
        Properties properties = new Properties();
        try (InputStream inputStream = BankingApplication.class.getClassLoader()
                .getResourceAsStream("banking.properties")) {
            if (inputStream != null) {
                properties.load(inputStream);
            }
        } catch (IOException e) {
            System.err.println("Failed to load banking.properties: " + e.getMessage());
        }
        return properties;
    }

    private static String resolve(Properties properties, String propertyKey, String envKey, String defaultValue) {
        String envValue = System.getenv(envKey);
        if (envValue != null && !envValue.isBlank()) {
            return envValue;
        }
        String sysValue = System.getProperty(propertyKey);
        if (sysValue != null && !sysValue.isBlank()) {
            return sysValue;
        }
        String fileValue = properties.getProperty(propertyKey);
        if (fileValue != null && !fileValue.isBlank()) {
            return fileValue;
        }
        return defaultValue;
    }
}
