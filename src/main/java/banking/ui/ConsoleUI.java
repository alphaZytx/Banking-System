package banking.ui;

import banking.api.BankHttpServer;
import banking.report.analytics.AnalyticsReportService;
import banking.report.analytics.AnomalyDetectionService;
import banking.report.analytics.RangeAnalyticsService;
import banking.report.analytics.TrendAnalyticsService;
import banking.report.format.ReportFormatter;
import banking.security.AuthenticationService;
import banking.security.TokenService;
import banking.service.Bank;
import banking.ui.console.ConsoleIO;
import banking.ui.flow.AccountCreationFlow;
import banking.ui.flow.AccountDirectoryFlow;
import banking.ui.flow.AccountManagementFlow;
import banking.ui.flow.AccountOperationsFlow;
import banking.ui.flow.ApiServerFlow;
import banking.ui.flow.ReportFlow;
import banking.ui.presenter.AccountPresenter;
import banking.ui.presenter.AnalyticsPresenter;
import banking.ui.presenter.StatementPresenter;
import banking.ui.presenter.TransactionPresenter;
import banking.report.AccountAnalyticsService;
import banking.report.StatementGenerator;

/**
 * Operator-facing console orchestrating the various teller workflows.
 */
public class ConsoleUI {
    private final Bank bank;
    private final ConsoleIO io;
    private final AccountCreationFlow accountCreationFlow;
    private final AccountDirectoryFlow accountDirectoryFlow;
    private final AccountOperationsFlow accountOperationsFlow;
    private final AccountManagementFlow accountManagementFlow;
    private final ReportFlow reportFlow;
    private final ApiServerFlow apiServerFlow;

    public ConsoleUI(Bank bank,
                     AuthenticationService authenticationService,
                     TokenService tokenService,
                     BankHttpServer httpServer) {
        this.bank = bank;
        this.io = new ConsoleIO();
        AccountPresenter accountPresenter = new AccountPresenter(io);
        TransactionPresenter transactionPresenter = new TransactionPresenter(io);
        this.accountCreationFlow = new AccountCreationFlow(bank, io, accountPresenter);
        this.accountDirectoryFlow = new AccountDirectoryFlow(bank, io, accountPresenter);
        this.accountOperationsFlow = new AccountOperationsFlow(bank, io, accountPresenter, transactionPresenter);
        this.accountManagementFlow = new AccountManagementFlow(bank, io, accountPresenter);
        StatementGenerator statementGenerator = new StatementGenerator();
        StatementPresenter statementPresenter = new StatementPresenter(io, transactionPresenter);
        AccountAnalyticsService analyticsService = new AccountAnalyticsService();
        AnalyticsPresenter analyticsPresenter = new AnalyticsPresenter(io);
        AnalyticsReportService analyticsReportService = new AnalyticsReportService(
                bank,
                new TrendAnalyticsService(),
                new AnomalyDetectionService(),
                new RangeAnalyticsService());
        ReportFormatter reportFormatter = new ReportFormatter();
        this.reportFlow = new ReportFlow(
                bank,
                io,
                accountPresenter,
                statementGenerator,
                statementPresenter,
                analyticsService,
                analyticsPresenter,
                analyticsReportService,
                reportFormatter);
        this.apiServerFlow = new ApiServerFlow(io, authenticationService, tokenService, httpServer);
    }

    public void start() {
        io.showWelcomeBanner("Advanced Banking System");
        boolean exit = false;

        while (!exit) {
            displayMainMenu();
            int choice = io.promptInt("Please select an option: ");

            switch (choice) {
                case 1 -> accountCreationFlow.createAccount();
                case 2 -> accountOperationsFlow.handleOperations();
                case 3 -> accountDirectoryFlow.showAllAccounts();
                case 4 -> accountDirectoryFlow.searchAccounts();
                case 5 -> reportFlow.showReportsMenu();
                case 6 -> accountManagementFlow.manageAccounts();
                case 7 -> apiServerFlow.manage();
                case 8 -> exit = exitApplication();
                default -> io.error("Invalid option. Please try again.");
            }
        }

        io.close();
    }

    private void displayMainMenu() {
        io.heading("Main Menu");
        io.info("1. Create New Account");
        io.info("2. Account Operations");
        io.info("3. View All Accounts");
        io.info("4. Search Accounts");
        io.info("5. Generate Reports");
        io.info("6. Account Management");
        io.info("7. API Server & Tokens");
        io.info("8. Exit");
    }

    private boolean exitApplication() {
        apiServerFlow.shutdown();
        bank.shutdown();
        io.success("Thank you for using our banking system. Goodbye!");
        return true;
    }
}
