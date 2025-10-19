package banking.transaction;

import java.time.LocalDateTime;

public class TransferReceiveTransaction extends BaseTransaction {
    private static final long serialVersionUID = 1L;

    private final int sourceAccountNumber;

    public TransferReceiveTransaction(double amount, int sourceAccountNumber) {
        super(amount);
        this.sourceAccountNumber = sourceAccountNumber;
    }

    public TransferReceiveTransaction(double amount, int sourceAccountNumber, LocalDateTime timestamp,
            String transactionId) {
        super(amount, timestamp, transactionId);
        this.sourceAccountNumber = sourceAccountNumber;
    }

    public TransferReceiveTransaction(double amount, int sourceAccountNumber, String transactionId,
            LocalDateTime timestamp) {
        super(amount, transactionId, timestamp);
        this.sourceAccountNumber = sourceAccountNumber;
    }

    public int getSourceAccountNumber() {
        return sourceAccountNumber;
    }

    @Override
    public String getType() {
        return "Received from Acc#" + sourceAccountNumber;
    }
}
