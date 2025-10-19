package banking.transaction;

import java.time.LocalDateTime;

public class InterestTransaction extends BaseTransaction {
    private static final long serialVersionUID = 1L;

    public InterestTransaction(double amount) {
        super(amount);
    }

    public InterestTransaction(double amount, LocalDateTime timestamp, String transactionId) {
        super(amount, timestamp, transactionId);
    }

    public InterestTransaction(double amount, String transactionId, LocalDateTime timestamp) {
        super(amount, transactionId, timestamp);
    }

    @Override
    public String getType() {
        return "Interest Added";
    }
}
