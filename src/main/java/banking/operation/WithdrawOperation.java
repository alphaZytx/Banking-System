package banking.operation;

import banking.account.Account;
import banking.persistence.AccountRepository;
import banking.persistence.PersistenceException;

import java.util.List;
import java.util.Objects;

/**
 * Withdraws funds from an account while enforcing business rules and persistence.
 */
public class WithdrawOperation implements AccountOperation {
    private final AccountRepository repository;
    private final int accountNumber;
    private final double amount;
    private Account affectedAccount;

    public WithdrawOperation(AccountRepository repository, int accountNumber, double amount) {
        this.repository = Objects.requireNonNull(repository, "repository");
        this.accountNumber = accountNumber;
        this.amount = amount;
    }

    @Override
    public OperationResult execute() {
        Account account = repository.findAccount(accountNumber);
        if (account == null) {
            return OperationResult.failure("Account not found: " + accountNumber);
        }
        try {
            if (account.withdraw(amount)) {
                repository.saveAccount(account);
                affectedAccount = account;
                return OperationResult.success(
                    "Withdrawal of " + amount + " completed for account " + accountNumber
                );
            }
            return OperationResult.failure("Withdrawal failed due to insufficient balance or account rules.");
        } catch (IllegalArgumentException e) {
            return OperationResult.failure("Withdrawal failed: " + e.getMessage());
        } catch (PersistenceException e) {
            return OperationResult.failure("Withdrawal persistence failed: " + e.getMessage());
        }
    }

    @Override
    public String getDescription() {
        return "Withdrawal of " + amount + " from account " + accountNumber;
    }

    @Override
    public List<Integer> getInvolvedAccountNumbers() {
        return List.of(accountNumber);
    }

    @Override
    public List<Account> getAffectedAccounts() {
        return affectedAccount == null ? List.of() : List.of(affectedAccount);
    }
}
