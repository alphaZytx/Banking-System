package banking.ui.flow;

import banking.account.Account;
import banking.report.AccountAnalyticsService;
import banking.report.AccountStatement;
import banking.report.AnalyticsReport;
import banking.report.AnalyticsReportRequest;
import banking.report.StatementGenerator;
import banking.report.analytics.AnalyticsRange;
import banking.report.analytics.AnalyticsReportService;
import banking.report.analytics.AnomalyReport;
import banking.report.analytics.RangeSummary;
import banking.report.analytics.TrendReport;
import banking.report.format.ReportFormatter;
import banking.service.Bank;
import banking.transaction.BaseTransaction;
import banking.ui.console.ConsoleIO;
import banking.ui.presenter.AccountPresenter;
import banking.ui.presenter.AnalyticsPresenter;
import banking.ui.presenter.StatementPresenter;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Coordinates the reporting workflows surfaced in the console.
 */
public class ReportFlow {
    private final Bank bank;
    private final ConsoleIO io;
    private final AccountPresenter accountPresenter;
    private final StatementGenerator statementGenerator;
    private final StatementPresenter statementPresenter;
    private final AccountAnalyticsService analyticsService;
    private final AnalyticsPresenter analyticsPresenter;
    private final AnalyticsReportService analyticsReportService;
    private final ReportFormatter reportFormatter;

    public ReportFlow(Bank bank,
            ConsoleIO io,
            AccountPresenter accountPresenter,
            StatementGenerator statementGenerator,
            StatementPresenter statementPresenter,
            AccountAnalyticsService analyticsService,
            AnalyticsPresenter analyticsPresenter,
            AnalyticsReportService analyticsReportService,
            ReportFormatter reportFormatter) {
        this.bank = bank;
        this.io = io;
        this.accountPresenter = accountPresenter;
        this.statementGenerator = statementGenerator;
        this.statementPresenter = statementPresenter;
        this.analyticsService = analyticsService;
        this.analyticsPresenter = analyticsPresenter;
        this.analyticsReportService = analyticsReportService;
        this.reportFormatter = reportFormatter;
    }

    public void showReportsMenu() {
        boolean back = false;
        while (!back) {
            io.heading("Reports");
            io.info("1. Account Summary Report");
            io.info("2. High-Value Accounts Report");
            io.info("3. Transaction Volume Report");
            io.info("4. Generate Account Statement");
            io.info("5. Portfolio Analytics Summary");
            io.info("6. Export Portfolio Analytics (CSV)");
            io.info("7. Export Portfolio Analytics (JSON)");
            io.info("8. Advanced Analytics Toolbox");
            io.info("9. Back to Main Menu");

            int choice = io.promptInt("Select a report to generate: ");
            switch (choice) {
                case 1 -> accountPresenter.showAccountSummary(bank.getAllAccounts());
                case 2 -> generateHighValueReport();
                case 3 -> generateTransactionVolumeReport();
                case 4 -> generateAccountStatement();
                case 5 -> generatePortfolioAnalyticsSummary();
                case 6 -> exportPortfolioAnalyticsCsv();
                case 7 -> exportPortfolioAnalyticsJson();
                case 8 -> advancedAnalyticsMenu();
                case 9 -> back = true;
                default -> io.error("Invalid choice!");
            }
        }
    }

    private void generateHighValueReport() {
        double threshold = io.promptDouble("Enter balance threshold for high-value accounts: ");
        accountPresenter.showHighValueAccounts(bank.getAllAccounts(), threshold);
    }

    private void generateTransactionVolumeReport() {
        List<BaseTransaction> allTransactions = bank.getAllAccounts().stream()
                .flatMap(account -> account.getTransactions().stream())
                .collect(Collectors.toList());

        if (allTransactions.isEmpty()) {
            io.warning("No transactions found in the system.");
            return;
        }

        Map<String, Integer> transactionTypeCount = new HashMap<>();
        allTransactions.forEach(transaction -> transactionTypeCount.merge(transaction.getType(), 1, Integer::sum));

        io.subHeading("Transaction Volume Report");
        transactionTypeCount.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .forEach(entry -> io.println(entry.getKey() + ": " + entry.getValue()));
    }

    private void generateAccountStatement() {
        int accountNumber = io.promptInt("Enter account number: ");
        Account account = bank.getAccount(accountNumber);
        if (account == null) {
            io.error("Account not found.");
            return;
        }

        LocalDate startDate = promptForDate("Enter start date (yyyy-MM-dd): ");
        LocalDate endDate = promptForDate("Enter end date (yyyy-MM-dd): ");
        if (endDate.isBefore(startDate)) {
            io.error("End date must not be before start date.");
            return;
        }

        AccountStatement statement = statementGenerator.generate(account, startDate, endDate);
        statementPresenter.show(statement);
    }

    private void generatePortfolioAnalyticsSummary() {
        AnalyticsReport report = runAnalyticsWorkflow();
        if (report != null) {
            analyticsPresenter.showSummary(report);
        }
    }

    private void exportPortfolioAnalyticsCsv() {
        AnalyticsReport report = runAnalyticsWorkflow();
        if (report != null) {
            String csv = analyticsPresenter.toCsv(report);
            io.subHeading("CSV Export");
            io.println(csv);
        }
    }

    private void exportPortfolioAnalyticsJson() {
        AnalyticsReport report = runAnalyticsWorkflow();
        if (report != null) {
            String json = analyticsPresenter.toJson(report);
            io.subHeading("JSON Export");
            io.println(json);
        }
    }

    private AnalyticsReport runAnalyticsWorkflow() {
        try {
            AnalyticsReportRequest request = promptAnalyticsRequest();
            io.info("Queuing analytics report... this may take a few moments.");
            return bank.generateAnalyticsReport(request, analyticsService).join();
        } catch (Exception ex) {
            io.error("Failed to generate analytics report: " + ex.getMessage());
            return null;
        }
    }

    private void advancedAnalyticsMenu() {
        boolean back = false;
        while (!back) {
            io.subHeading("Advanced Analytics");
            io.info("1. Transaction Trend (JSON)");
            io.info("2. Transaction Trend (CSV)");
            io.info("3. Anomaly Detection (JSON)");
            io.info("4. Anomaly Detection (CSV)");
            io.info("5. Range KPIs (JSON)");
            io.info("6. Range KPIs (CSV)");
            io.info("7. Back");
            int choice = io.promptInt("Choose an option: ");
            switch (choice) {
                case 1 -> showTrendReportJson();
                case 2 -> showTrendReportCsv();
                case 3 -> showAnomalyReportJson();
                case 4 -> showAnomalyReportCsv();
                case 5 -> showRangeSummaryJson();
                case 6 -> showRangeSummaryCsv();
                case 7 -> back = true;
                default -> io.error("Invalid choice.");
            }
        }
    }

    private void showTrendReportJson() {
        AnalyticsRange range = promptAnalyticsRange();
        TrendReport report = analyticsReportService.queueTrendReport(range).join();
        io.subHeading("Trend Report (JSON)");
        io.println(reportFormatter.toJson(report));
    }

    private void showTrendReportCsv() {
        AnalyticsRange range = promptAnalyticsRange();
        TrendReport report = analyticsReportService.queueTrendReport(range).join();
        io.subHeading("Trend Report (CSV)");
        io.println(reportFormatter.toCsv(report));
    }

    private void showAnomalyReportJson() {
        AnalyticsRange range = promptAnalyticsRange();
        double threshold = io.promptDouble("Absolute amount threshold (e.g. 5000): ");
        double deviation = io.promptDouble("Deviation multiplier (e.g. 3 for 3σ): ");
        AnomalyReport report = analyticsReportService.queueAnomalyReport(range, threshold, deviation).join();
        io.subHeading("Anomaly Report (JSON)");
        io.println(reportFormatter.toJson(report));
    }

    private void showAnomalyReportCsv() {
        AnalyticsRange range = promptAnalyticsRange();
        double threshold = io.promptDouble("Absolute amount threshold (e.g. 5000): ");
        double deviation = io.promptDouble("Deviation multiplier (e.g. 3 for 3σ): ");
        AnomalyReport report = analyticsReportService.queueAnomalyReport(range, threshold, deviation).join();
        io.subHeading("Anomaly Report (CSV)");
        io.println(reportFormatter.toCsv(report));
    }

    private void showRangeSummaryJson() {
        AnalyticsRange range = promptAnalyticsRange();
        RangeSummary summary = analyticsReportService.queueRangeSummary(range).join();
        io.subHeading("Range Summary (JSON)");
        io.println(reportFormatter.toJson(summary));
    }

    private void showRangeSummaryCsv() {
        AnalyticsRange range = promptAnalyticsRange();
        RangeSummary summary = analyticsReportService.queueRangeSummary(range).join();
        io.subHeading("Range Summary (CSV)");
        io.println(reportFormatter.toCsv(summary));
    }

    private AnalyticsReportRequest promptAnalyticsRequest() {
        LocalDate defaultStart = LocalDate.now().minusDays(30);
        LocalDate defaultEnd = LocalDate.now();
        io.info("Press ENTER to accept defaults.");
        LocalDate startDate = promptOptionalDate("Enter analytics start date (yyyy-MM-dd)", defaultStart);
        LocalDate endDate = promptOptionalDate("Enter analytics end date (yyyy-MM-dd)", defaultEnd);
        String thresholdInput = io.prompt("Enter high-value threshold (default 5000): ");
        double threshold;
        if (thresholdInput == null || thresholdInput.isBlank()) {
            threshold = 5000.0;
        } else {
            try {
                threshold = Double.parseDouble(thresholdInput.trim());
            } catch (NumberFormatException e) {
                io.warning("Invalid threshold provided. Using default (5000).");
                threshold = 5000.0;
            }
        }

        String windowInput = io.prompt("Enter rolling window (days, default 7): ");
        int window;
        if (windowInput == null || windowInput.isBlank()) {
            window = 7;
        } else {
            try {
                window = Integer.parseInt(windowInput.trim());
                if (window <= 0) {
                    io.warning("Rolling window must be positive. Using default (7).");
                    window = 7;
                }
            } catch (NumberFormatException e) {
                io.warning("Invalid window provided. Using default (7).");
                window = 7;
            }
        }

        return AnalyticsReportRequest.builder()
                .withStartDate(startDate)
                .withEndDate(endDate)
                .withLargeTransactionThreshold(threshold)
                .withRollingWindowDays(window)
                .build();
    }

    private AnalyticsRange promptAnalyticsRange() {
        LocalDate start = promptOptionalDate("Start date (yyyy-MM-dd)", LocalDate.now().minusDays(30));
        LocalDate end = promptOptionalDate("End date (yyyy-MM-dd)", LocalDate.now());
        return new AnalyticsRange(start, end);
    }

    private LocalDate promptForDate(String prompt) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");
        while (true) {
            try {
                return LocalDate.parse(io.prompt(prompt), formatter);
            } catch (DateTimeParseException ex) {
                io.error("Invalid date format. Please use yyyy-MM-dd.");
            }
        }
    }

    private LocalDate promptOptionalDate(String prompt, LocalDate defaultValue) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");
        while (true) {
            String input = io.prompt(prompt + " [" + defaultValue + "]: ");
            if (input == null || input.isBlank()) {
                return defaultValue;
            }
            try {
                return LocalDate.parse(input.trim(), formatter);
            } catch (DateTimeParseException ex) {
                io.error("Invalid date format. Please use yyyy-MM-dd.");
            }
        }
    }
}
