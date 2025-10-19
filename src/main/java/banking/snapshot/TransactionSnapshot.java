package banking.snapshot;

import java.util.Objects;

/**
 * Serializable representation of a banking transaction.
 */
public record TransactionSnapshot(TransactionType type, double amount, String timestamp, String transactionId,
        Integer sourceAccount, Integer targetAccount) {
    public TransactionSnapshot {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(timestamp, "timestamp");
        Objects.requireNonNull(transactionId, "transactionId");
    }
}
