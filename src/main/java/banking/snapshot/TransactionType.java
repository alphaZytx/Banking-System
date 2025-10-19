package banking.snapshot;

/**
 * Canonical transaction categories used when persisting account history to the
 * durable snapshot store.
 */
public enum TransactionType {
    DEPOSIT,
    WITHDRAWAL,
    INTEREST,
    TRANSFER_OUT,
    TRANSFER_IN
}
