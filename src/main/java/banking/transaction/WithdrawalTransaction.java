package banking.transaction;

import java.time.LocalDateTime;

public class WithdrawalTransaction extends BaseTransaction {
    private static final long serialVersionUID = 1L;

    public WithdrawalTransaction(double amount) {
        super(amount);
    }

    public WithdrawalTransaction(double amount, LocalDateTime timestamp, String transactionId) {
        super(amount, timestamp, transactionId);
    }

    public WithdrawalTransaction(double amount, String transactionId, LocalDateTime timestamp) {
        super(amount, transactionId, timestamp);
    }

    @Override
    public String getType() {
        return "Withdrawal";
    }
}
