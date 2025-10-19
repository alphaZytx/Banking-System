package banking.snapshot;

import java.util.List;
import java.util.Objects;

/**
 * Root snapshot capturing the persistent state of the banking system.
 */
public record BankSnapshot(int version, List<AccountSnapshot> accounts) {
    public static final int CURRENT_VERSION = 1;

    public BankSnapshot {
        if (version <= 0) {
            throw new IllegalArgumentException("version must be positive");
        }
        Objects.requireNonNull(accounts, "accounts");
        accounts = List.copyOf(accounts);
    }
}
