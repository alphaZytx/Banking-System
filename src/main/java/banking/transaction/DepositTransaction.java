package banking.transaction;

import java.time.LocalDateTime;

public class DepositTransaction extends BaseTransaction {
    private static final long serialVersionUID = 1L;

    public DepositTransaction(double amount) {
        super(amount);
    }

    public DepositTransaction(double amount, LocalDateTime timestamp, String transactionId) {
        super(amount, timestamp, transactionId);
    }

    public DepositTransaction(double amount, String transactionId, LocalDateTime timestamp) {
        super(amount, transactionId, timestamp);
    }

    @Override
    public String getType() {
        return "Deposit";
    }
}
