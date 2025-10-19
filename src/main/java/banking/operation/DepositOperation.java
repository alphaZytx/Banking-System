package banking.operation;

import banking.account.Account;
import banking.persistence.AccountRepository;
import banking.persistence.PersistenceException;

import java.util.List;
import java.util.Objects;

/**
 * Deposits funds into an account and persists the updated state.
 */
public class DepositOperation implements AccountOperation {
    private final AccountRepository repository;
    private final int accountNumber;
    private final double amount;
    private Account affectedAccount;

    public DepositOperation(AccountRepository repository, int accountNumber, double amount) {
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
            account.deposit(amount);
            repository.saveAccount(account);
            affectedAccount = account;
            return OperationResult.success(
                "Deposit of " + amount + " completed for account " + accountNumber
            );
        } catch (IllegalArgumentException e) {
            return OperationResult.failure("Deposit failed: " + e.getMessage());
        } catch (PersistenceException e) {
            return OperationResult.failure("Deposit persistence failed: " + e.getMessage());
        }
    }

    @Override
    public String getDescription() {
        return "Deposit of " + amount + " to account " + accountNumber;
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
