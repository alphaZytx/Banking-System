package banking.transaction;

import java.time.LocalDateTime;

public class TransferTransaction extends BaseTransaction {
    private static final long serialVersionUID = 1L;

    private final int targetAccountNumber;

    public TransferTransaction(double amount, int targetAccountNumber) {
        super(amount);
        this.targetAccountNumber = targetAccountNumber;
    }

    public TransferTransaction(double amount, int targetAccountNumber, LocalDateTime timestamp, String transactionId) {
        super(amount, timestamp, transactionId);
        this.targetAccountNumber = targetAccountNumber;
    }

    public TransferTransaction(double amount, int targetAccountNumber, String transactionId, LocalDateTime timestamp) {
        super(amount, transactionId, timestamp);
        this.targetAccountNumber = targetAccountNumber;
    }

    public int getTargetAccountNumber() {
        return targetAccountNumber;
    }

    @Override
    public String getType() {
        return "Transfer to Acc#" + targetAccountNumber;
    }
}
