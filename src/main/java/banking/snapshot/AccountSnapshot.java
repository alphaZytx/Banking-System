package banking.snapshot;

import java.util.List;
import java.util.Objects;

/**
 * Snapshot of an account used for persistence and migration.
 */
public record AccountSnapshot(String accountType, int accountNumber, String userName, double balance,
        String creationDate, Double minimumBalance, Double overdraftLimit, Integer termMonths, String maturityDate,
        List<TransactionSnapshot> transactions) {
    public AccountSnapshot {
        Objects.requireNonNull(accountType, "accountType");
        Objects.requireNonNull(userName, "userName");
        Objects.requireNonNull(creationDate, "creationDate");
        Objects.requireNonNull(transactions, "transactions");
        transactions = List.copyOf(transactions);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String accountType;
        private Integer accountNumber;
        private String userName;
        private Double balance;
        private String creationDate;
        private Double minimumBalance;
        private Double overdraftLimit;
        private Integer termMonths;
        private String maturityDate;
        private final List<TransactionSnapshot> transactions = new java.util.ArrayList<>();

        private Builder() {
        }

        public Builder accountType(String accountType) {
            this.accountType = accountType;
            return this;
        }

        public Builder accountNumber(int accountNumber) {
            this.accountNumber = accountNumber;
            return this;
        }

        public Builder userName(String userName) {
            this.userName = userName;
            return this;
        }

        public Builder balance(double balance) {
            this.balance = balance;
            return this;
        }

        public Builder creationDate(String creationDate) {
            this.creationDate = creationDate;
            return this;
        }

        public Builder minimumBalance(Double minimumBalance) {
            this.minimumBalance = minimumBalance;
            return this;
        }

        public Builder overdraftLimit(Double overdraftLimit) {
            this.overdraftLimit = overdraftLimit;
            return this;
        }

        public Builder termMonths(Integer termMonths) {
            this.termMonths = termMonths;
            return this;
        }

        public Builder maturityDate(String maturityDate) {
            this.maturityDate = maturityDate;
            return this;
        }

        public Builder addTransaction(TransactionSnapshot snapshot) {
            this.transactions.add(snapshot);
            return this;
        }

        public AccountSnapshot build() {
            if (accountType == null || accountNumber == null || userName == null || balance == null
                    || creationDate == null) {
                throw new IllegalStateException("AccountSnapshot is missing required fields");
            }
            return new AccountSnapshot(accountType, accountNumber, userName, balance, creationDate, minimumBalance,
                    overdraftLimit, termMonths, maturityDate, transactions);
        }
    }
}
