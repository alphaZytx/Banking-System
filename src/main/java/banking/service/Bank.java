package banking.service;

import banking.account.Account;
import banking.account.AccountFactory;
import banking.account.CurrentAccount;
import banking.account.FixedDepositAccount;
import banking.account.SavingsAccount;
import banking.observer.AccountObserver;
import banking.observer.ConsoleNotifier;
import banking.observer.TransactionLogger;
import banking.operation.AccountOperation;
import banking.operation.DepositOperation;
import banking.operation.OperationResult;
import banking.operation.TransferOperation;
import banking.operation.WithdrawOperation;
import banking.persistence.AccountRepository;
import banking.persistence.PersistenceException;
import banking.persistence.memory.InMemoryAccountRepository;
import banking.report.AccountAnalyticsService;
import banking.report.AnalyticsReportOperation;
import banking.report.AnalyticsReport;
import banking.report.AnalyticsReportRequest;
import banking.snapshot.AccountSnapshot;
import banking.snapshot.BankSnapshot;
import banking.snapshot.TransactionSnapshot;
import banking.snapshot.TransactionType;
import banking.transaction.BaseTransaction;
import banking.transaction.DepositTransaction;
import banking.transaction.InterestTransaction;
import banking.transaction.TransferReceiveTransaction;
import banking.transaction.TransferTransaction;
import banking.transaction.WithdrawalTransaction;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Queue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * Core banking aggregate coordinating account lifecycle and operations.
 */
public class Bank implements AutoCloseable {
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final Map<Integer, Account> accounts;
    private final AccountRepository repository;
    private final Map<Integer, ReentrantLock> accountLocks;
    private final List<AccountObserver> observers;
    private final Queue<QueuedOperation> operationQueue;
    private final ExecutorService executorService;
    private final List<CompletableFuture<OperationResult>> pendingOperations;
    private final List<CompletableFuture<?>> backgroundTasks;

    public Bank() {
        this(new InMemoryAccountRepository());
    }

    public Bank(AccountRepository repository) {
        this(repository, loadAccounts(repository));
    }

    private Bank(AccountRepository repository, Map<Integer, Account> initialAccounts) {
        this.repository = Objects.requireNonNull(repository, "repository");
        this.accounts = new HashMap<>(Objects.requireNonNull(initialAccounts, "initialAccounts"));
        this.accountLocks = new ConcurrentHashMap<>();
        this.observers = new CopyOnWriteArrayList<>();
        this.operationQueue = new ConcurrentLinkedQueue<>();
        this.executorService = Executors.newFixedThreadPool(5);
        this.pendingOperations = new CopyOnWriteArrayList<>();
        this.backgroundTasks = new CopyOnWriteArrayList<>();

        accounts.keySet().forEach(number -> accountLocks.put(number, new ReentrantLock()));

        addObserver(new ConsoleNotifier());
        addObserver(new TransactionLogger());
    }

    private static Map<Integer, Account> loadAccounts(AccountRepository repository) {
        Map<Integer, Account> loaded = new HashMap<>();
        for (Account account : repository.findAllAccounts()) {
            loaded.put(account.getAccountNumber(), account);
        }
        return loaded;
    }

    public static Bank restore(BankSnapshot snapshot) {
        Map<Integer, Account> restored = new HashMap<>();
        for (AccountSnapshot accountSnapshot : snapshot.accounts()) {
            Account account = AccountFactory.restoreAccount(accountSnapshot);
            restored.put(account.getAccountNumber(), account);
        }
        InMemoryAccountRepository repository = new InMemoryAccountRepository();
        repository.saveAccounts(restored.values());
        return new Bank(repository, restored);
    }

    public synchronized BankSnapshot snapshot() {
        List<AccountSnapshot> accountSnapshots = accounts.values().stream()
                .sorted(Comparator.comparingInt(Account::getAccountNumber))
                .map(Bank::toSnapshot)
                .collect(Collectors.toList());
        return new BankSnapshot(BankSnapshot.CURRENT_VERSION, accountSnapshots);
    }

    private static AccountSnapshot toSnapshot(Account account) {
        List<TransactionSnapshot> transactions = account.getTransactions().stream()
                .map(Bank::toSnapshot)
                .collect(Collectors.toCollection(ArrayList::new));

        Double minimumBalance = null;
        Double overdraftLimit = null;
        Integer termMonths = null;
        String maturityDate = null;

        if (account instanceof SavingsAccount savingsAccount) {
            minimumBalance = savingsAccount.getMinimumBalance();
        } else if (account instanceof CurrentAccount currentAccount) {
            overdraftLimit = currentAccount.getOverdraftLimit();
        } else if (account instanceof FixedDepositAccount fixedDepositAccount) {
            termMonths = fixedDepositAccount.getTermMonths();
            LocalDateTime maturity = fixedDepositAccount.getMaturityDate();
            maturityDate = maturity != null ? maturity.toString() : null;
        }

        return new AccountSnapshot(account.getAccountType().toUpperCase(Locale.ROOT), account.getAccountNumber(),
                account.getUserName(), account.getBalance(), account.getCreationDate(), minimumBalance, overdraftLimit,
                termMonths, maturityDate, transactions);
    }

    private static TransactionSnapshot toSnapshot(BaseTransaction transaction) {
        TransactionType type;
        Integer sourceAccount = null;
        Integer targetAccount = null;

        if (transaction instanceof DepositTransaction) {
            type = TransactionType.DEPOSIT;
        } else if (transaction instanceof WithdrawalTransaction) {
            type = TransactionType.WITHDRAWAL;
        } else if (transaction instanceof InterestTransaction) {
            type = TransactionType.INTEREST;
        } else if (transaction instanceof TransferTransaction transferTransaction) {
            type = TransactionType.TRANSFER_OUT;
            targetAccount = transferTransaction.getTargetAccountNumber();
        } else if (transaction instanceof TransferReceiveTransaction receiveTransaction) {
            type = TransactionType.TRANSFER_IN;
            sourceAccount = receiveTransaction.getSourceAccountNumber();
        } else {
            throw new IllegalArgumentException("Unsupported transaction type: " + transaction.getClass());
        }

        return new TransactionSnapshot(type, transaction.getAmount(), transaction.getTimestamp().toString(),
                transaction.getTransactionId(), sourceAccount, targetAccount);
    }

    public synchronized void addObserver(AccountObserver observer) {
        observers.add(Objects.requireNonNull(observer, "observer"));
    }

    public synchronized Account createAccount(String userName, String accountType, double initialDeposit) {
        int accountNumber = generateAccountNumber();
        Account account = AccountFactory.createAccount(accountType, userName, accountNumber, initialDeposit);
        accounts.put(accountNumber, account);
        accountLocks.putIfAbsent(accountNumber, new ReentrantLock());

        try {
            repository.saveAccount(account);
            notifyObservers("New " + account.getAccountType() + " account created for " + userName
                    + ", Account#: " + accountNumber);
            return account;
        } catch (PersistenceException e) {
            accounts.remove(accountNumber);
            accountLocks.remove(accountNumber);
            throw e;
        }
    }

    public synchronized boolean closeAccount(int accountNumber) {
        Account account = accounts.remove(accountNumber);
        if (account == null) {
            return false;
        }
        try {
            boolean deleted = repository.deleteAccount(accountNumber);
            if (!deleted) {
                accounts.put(accountNumber, account);
                return false;
            }
            accountLocks.remove(accountNumber);
            notifyObservers("Account closed: " + accountNumber + " for " + account.getUserName());
            return true;
        } catch (PersistenceException e) {
            accounts.put(accountNumber, account);
            throw e;
        }
    }

    public synchronized boolean updateAccountHolderName(int accountNumber, String newName) {
        Account account = accounts.get(accountNumber);
        if (account == null) {
            return false;
        }

        account.setUserName(newName);
        try {
            repository.saveAccount(account);
            notifyObservers("Account holder updated for account " + accountNumber + " to " + account.getUserName());
            return true;
        } catch (PersistenceException e) {
            throw e;
        }
    }

    public synchronized Account getAccount(int accountNumber) {
        return accounts.get(accountNumber);
    }

    public synchronized List<Account> getAllAccounts() {
        return new ArrayList<>(accounts.values());
    }

    public synchronized int getPendingOperationCount() {
        return pendingOperations.size();
    }

    public synchronized List<Account> getAccountsByType(String accountType) {
        return accounts.values().stream()
                .filter(a -> a.getAccountType().toLowerCase(Locale.ROOT).contains(accountType.toLowerCase(Locale.ROOT)))
                .collect(Collectors.toList());
    }

    public synchronized List<Account> searchAccounts(String keyword) {
        String lowercaseKeyword = keyword.toLowerCase(Locale.ROOT);
        return accounts.values().stream()
                .filter(a -> a.getUserName().toLowerCase(Locale.ROOT).contains(lowercaseKeyword))
                .collect(Collectors.toList());
    }

    public CompletableFuture<AnalyticsReport> generateAnalyticsReport(AnalyticsReportRequest request,
            AccountAnalyticsService analyticsService) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(analyticsService, "analyticsService");
        List<banking.report.AccountSnapshot> snapshots = analyticsSnapshots();
        AnalyticsReportOperation operation = new AnalyticsReportOperation(request, analyticsService, snapshots);
        CompletableFuture<AnalyticsReport> reportFuture = operation.getReportFuture();
        CompletableFuture<OperationResult> operationFuture = queueOperation(operation);
        operationFuture.whenComplete((result, error) -> {
            if (error != null) {
                reportFuture.completeExceptionally(error);
            } else if (!result.isSuccess() && !reportFuture.isDone()) {
                reportFuture.completeExceptionally(new IllegalStateException(result.getMessage()));
            }
        });
        return reportFuture;
    }

    public synchronized CompletableFuture<OperationResult> deposit(int accountNumber, double amount) {
        if (!accounts.containsKey(accountNumber)) {
            return CompletableFuture.completedFuture(
                    OperationResult.failure("Account not found: " + accountNumber));
        }
        return queueOperation(new DepositOperation(repository, accountNumber, amount));
    }

    public synchronized CompletableFuture<OperationResult> withdraw(int accountNumber, double amount) {
        if (!accounts.containsKey(accountNumber)) {
            return CompletableFuture.completedFuture(
                    OperationResult.failure("Account not found: " + accountNumber));
        }
        return queueOperation(new WithdrawOperation(repository, accountNumber, amount));
    }

    public synchronized CompletableFuture<OperationResult> transfer(int sourceAccountNumber, int targetAccountNumber,
            double amount) {
        if (!accounts.containsKey(sourceAccountNumber)) {
            return CompletableFuture.completedFuture(
                    OperationResult.failure("Source account not found: " + sourceAccountNumber));
        }
        if (!accounts.containsKey(targetAccountNumber)) {
            return CompletableFuture.completedFuture(
                    OperationResult.failure("Target account not found: " + targetAccountNumber));
        }
        try {
            return queueOperation(new TransferOperation(repository, sourceAccountNumber, targetAccountNumber, amount));
        } catch (IllegalArgumentException e) {
            return CompletableFuture.completedFuture(OperationResult.failure(e.getMessage()));
        }
    }

    public synchronized CompletableFuture<OperationResult> queueOperation(AccountOperation operation) {
        Objects.requireNonNull(operation, "operation");
        CompletableFuture<OperationResult> future = new CompletableFuture<>();
        pendingOperations.add(future);
        operationQueue.add(new QueuedOperation(operation, future));
        executePendingOperations();
        return future;
    }

    public <T> CompletableFuture<T> submitAnalyticsTask(Supplier<T> task, String description) {
        Objects.requireNonNull(task, "task");
        Objects.requireNonNull(description, "description");

        CompletableFuture<T> future = new CompletableFuture<>();
        synchronized (this) {
            backgroundTasks.add(future);
            try {
                executorService.submit(() -> runAnalyticsTask(task, description, future));
            } catch (RejectedExecutionException e) {
                backgroundTasks.remove(future);
                notifyObservers("FAILED: " + description + " rejected during shutdown");
                future.completeExceptionally(new IllegalStateException(
                        "Analytics task rejected during shutdown: " + description, e));
            }
        }
        return future;
    }

    public synchronized void executePendingOperations() {
        while (!operationQueue.isEmpty()) {
            QueuedOperation queued = operationQueue.poll();
            if (queued == null) {
                continue;
            }
            try {
                executorService.submit(() -> runOperation(queued));
            } catch (RejectedExecutionException e) {
                OperationResult result = OperationResult.failure(
                        "Operation rejected during shutdown: " + queued.operation().getDescription());
                notifyObservers("FAILED: " + result.getMessage());
                queued.future().complete(result);
                pendingOperations.remove(queued.future());
            }
        }
    }

    public void shutdown() {
        awaitPendingOperations();
        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
        }
        try {
            repository.close();
        } catch (Exception e) {
            System.err.println("Failed to close repository: " + e.getMessage());
        }
    }

    @Override
    public void close() {
        shutdown();
    }

    public synchronized int addInterestToAllSavingsAccounts() {
        List<Account> updatedAccounts = new ArrayList<>();
        for (Account account : accounts.values()) {
            if (account instanceof SavingsAccount || account instanceof FixedDepositAccount) {
                account.addInterest();
                updatedAccounts.add(account);
            }
        }

        if (!updatedAccounts.isEmpty()) {
            repository.saveAccounts(updatedAccounts);
            notifyObservers("Monthly interest added to " + updatedAccounts.size() + " eligible accounts");
        } else {
            notifyObservers("No eligible accounts found for monthly interest processing");
        }

        return updatedAccounts.size();
    }

    private void runOperation(QueuedOperation queued) {
        AccountOperation operation = queued.operation();
        List<ReentrantLock> locks = acquireLocks(operation);
        OperationResult result;
        try {
            result = operation.execute();
            if (result.isSuccess()) {
                updateAccounts(operation.getAffectedAccounts());
            }
        } catch (Exception e) {
            result = OperationResult.failure("Unexpected error executing operation: " + e.getMessage());
        } finally {
            releaseLocks(locks);
        }

        notifyObservers(result.isSuccess()
                ? "SUCCESS: " + result.getMessage()
                : "FAILED: " + result.getMessage());
        try {
            queued.future().complete(result);
        } finally {
            pendingOperations.remove(queued.future());
        }
    }

    private <T> void runAnalyticsTask(Supplier<T> task, String description, CompletableFuture<T> future) {
        try {
            T result = task.get();
            notifyObservers("SUCCESS: " + description);
            future.complete(result);
        } catch (Exception e) {
            notifyObservers("FAILED: " + description + " -> " + e.getMessage());
            future.completeExceptionally(e);
        } finally {
            backgroundTasks.remove(future);
        }
    }

    private List<ReentrantLock> acquireLocks(AccountOperation operation) {
        List<Integer> accountNumbers = operation.getInvolvedAccountNumbers();
        if (accountNumbers.isEmpty()) {
            return Collections.emptyList();
        }
        List<Integer> sorted = new ArrayList<>(accountNumbers.stream().distinct().collect(Collectors.toList()));
        Collections.sort(sorted);
        List<ReentrantLock> locks = new ArrayList<>(sorted.size());
        for (Integer number : sorted) {
            ReentrantLock lock = accountLocks.computeIfAbsent(number, key -> new ReentrantLock());
            lock.lock();
            locks.add(lock);
        }
        return locks;
    }

    private void releaseLocks(List<ReentrantLock> locks) {
        for (ReentrantLock lock : locks) {
            lock.unlock();
        }
    }

    private void updateAccounts(Collection<Account> updatedAccounts) {
        if (updatedAccounts == null || updatedAccounts.isEmpty()) {
            return;
        }
        synchronized (this) {
            for (Account account : updatedAccounts) {
                accounts.put(account.getAccountNumber(), account);
                accountLocks.computeIfAbsent(account.getAccountNumber(), key -> new ReentrantLock());
            }
        }
    }

    private void notifyObservers(String message) {
        for (AccountObserver observer : observers) {
            try {
                observer.update(message);
            } catch (RuntimeException e) {
                System.err.println("Observer notification failed: " + e.getMessage());
            }
        }
    }

    private synchronized List<banking.report.AccountSnapshot> analyticsSnapshots() {
        return accounts.values().stream()
                .map(banking.report.AccountSnapshot::fromAccount)
                .collect(Collectors.toList());
    }

    public void awaitPendingOperations() {
        while (true) {
            CompletableFuture<?>[] operationFutures;
            CompletableFuture<?>[] analyticsFutures;
            synchronized (this) {
                executePendingOperations();
                if (pendingOperations.isEmpty() && backgroundTasks.isEmpty()) {
                    return;
                }
                operationFutures = pendingOperations.toArray(new CompletableFuture[0]);
                analyticsFutures = backgroundTasks.toArray(new CompletableFuture[0]);
            }
            CompletableFuture<?>[] all = new CompletableFuture[operationFutures.length + analyticsFutures.length];
            int index = 0;
            for (CompletableFuture<?> future : operationFutures) {
                all[index++] = future;
            }
            for (CompletableFuture<?> future : analyticsFutures) {
                all[index++] = future;
            }
            CompletableFuture.allOf(all).join();
        }
    }

    private int generateAccountNumber() {
        int accountNumber;
        do {
            accountNumber = 100000 + SECURE_RANDOM.nextInt(900000);
        } while (accounts.containsKey(accountNumber));
        return accountNumber;
    }

    private record QueuedOperation(AccountOperation operation, CompletableFuture<OperationResult> future) {
    }
}
