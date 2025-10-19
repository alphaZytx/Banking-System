package banking.operation;

import banking.account.Account;
import banking.persistence.AccountRepository;
import banking.persistence.PersistenceException;

import java.util.List;
import java.util.Objects;

/**
 * Moves funds between two accounts in a single atomic operation.
 */
public class TransferOperation implements AccountOperation {
    private final AccountRepository repository;
    private final int sourceAccountNumber;
    private final int targetAccountNumber;
    private final double amount;
    private List<Account> affectedAccounts = List.of();

    public TransferOperation(AccountRepository repository, int sourceAccountNumber, int targetAccountNumber,
            double amount) {
        if (sourceAccountNumber == targetAccountNumber) {
            throw new IllegalArgumentException("Source and target accounts must be different");
        }
        this.repository = Objects.requireNonNull(repository, "repository");
        this.sourceAccountNumber = sourceAccountNumber;
        this.targetAccountNumber = targetAccountNumber;
        this.amount = amount;
    }

    @Override
    public OperationResult execute() {
        Account source = repository.findAccount(sourceAccountNumber);
        if (source == null) {
            return OperationResult.failure("Source account not found: " + sourceAccountNumber);
        }
        Account target = repository.findAccount(targetAccountNumber);
        if (target == null) {
            return OperationResult.failure("Target account not found: " + targetAccountNumber);
        }
        try {
            if (source.transfer(amount, target)) {
                repository.saveAccounts(List.of(source, target));
                affectedAccounts = List.of(source, target);
                return OperationResult.success("Transfer of " + amount + " completed from account "
                        + sourceAccountNumber + " to account " + targetAccountNumber);
            }
            return OperationResult.failure("Transfer failed due to insufficient balance or account rules.");
        } catch (IllegalArgumentException e) {
            return OperationResult.failure("Transfer failed: " + e.getMessage());
        } catch (PersistenceException e) {
            return OperationResult.failure("Transfer persistence failed: " + e.getMessage());
        }
    }

    @Override
    public String getDescription() {
        return "Transfer of " + amount + " from account " + sourceAccountNumber
                + " to account " + targetAccountNumber;
    }

    @Override
    public List<Integer> getInvolvedAccountNumbers() {
        return List.of(sourceAccountNumber, targetAccountNumber);
    }

    @Override
    public List<Account> getAffectedAccounts() {
        return affectedAccounts;
    }
}
