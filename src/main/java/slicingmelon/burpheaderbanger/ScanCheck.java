package slicingmelon.burpheaderbanger;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ScheduledExecutorService;

import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_EXISTING;
import static java.util.Collections.emptyList;

public class ScanCheck implements ActiveScanCheck, PassiveScanCheck, ContextMenuItemsProvider {
    private final BurpHeaderBanger extension;
    private final MontoyaApi api;
    private final ScheduledExecutorService scheduler;
    private final CollaboratorClient collaboratorClient;
    private final Map<String, PayloadCorrelation> payloadMap;
    private final AuditIssueBuilder auditIssueCreator;

    public ScanCheck(BurpHeaderBanger extension, MontoyaApi api, ScheduledExecutorService scheduler,
                    CollaboratorClient collaboratorClient, Map<String, PayloadCorrelation> payloadMap,
                    AuditIssueBuilder auditIssueCreator) {
        this.extension = extension;
        this.api = api;
        this.scheduler = scheduler;
        this.collaboratorClient = collaboratorClient;
        this.payloadMap = payloadMap;
        this.auditIssueCreator = auditIssueCreator;
    }

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

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();
        
        JMenuItem scanItem = new JMenuItem("Scan this request with Header Banger");
        scanItem.addActionListener(_ -> scanSelectedRequest(event));
        menuItems.add(scanItem);
        
        JMenuItem excludeHostItem = new JMenuItem("Exclude Host from Header Banger scans");
        excludeHostItem.addActionListener(_ -> excludeHostFromScans(event));
        menuItems.add(excludeHostItem);
        
        JMenuItem excludeUrlItem = new JMenuItem("Exclude URL from Header Banger scans");
        excludeUrlItem.addActionListener(_ -> excludeUrlFromScans(event));
        menuItems.add(excludeUrlItem);
        
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
                    if (extension.getAttackMode() == 2) {
                        api.logging().logToOutput("Context menu: Processing BXSS for sensitive headers");
                        
                        // BXSS logic for context menu
                        List<HttpHeader> modifiedHeaders = new ArrayList<>(originalRequest.headers());
                        
                        for (String sensitiveHeader : extension.getSensitiveHeaders()) {
                            String finalPayload;
                            
                            // Check if payload uses collaborator tracking
                            if (extension.getBxssPayload().contains("{{collaborator}}")) {
                                // Generate collaborator payload and do tracking
                                CollaboratorPayload collabPayload = collaboratorClient.generatePayload();
                                String payloadDomain = collabPayload.toString();
                                finalPayload = hostValue + extension.getBxssPayload().replace("{{collaborator}}", payloadDomain);
                                
                                // Store correlation for collaborator tracking
                                PayloadCorrelation correlation = new PayloadCorrelation(originalRequest.url(), sensitiveHeader, originalRequest.method());
                                payloadMap.put(payloadDomain, correlation);
                                
                                api.logging().logToOutput("Context menu: Added payload to map: " + payloadDomain + " -> " + sensitiveHeader);
                            } else {
                                // Custom payload without collaborator - no tracking needed
                                finalPayload = hostValue + extension.getBxssPayload();
                                
                                api.logging().logToOutput("Context menu: Using custom payload (no collaborator tracking): " + sensitiveHeader);
                            }
                            
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
                        HttpRequest finalRequest = originalRequest.withUpdatedHeaders(addOrReplaceHeaders(modifiedHeaders, extension.getExtraHeaders()));
                        
                        api.logging().logToOutput("Context menu: Sending request with " + extension.getSensitiveHeaders().size() + " sensitive headers");
                        api.logging().logToOutput("Context menu: Total payloads in map: " + payloadMap.size());
                        
                        api.http().sendRequest(finalRequest);
                        api.logging().logToOutput("Context menu scan: Sent BXSS probes for sensitive headers for URL: " + originalRequest.url());
                        return;
                    }

                    api.logging().logToOutput("Context menu: Processing SQL injection for sensitive headers");
                    
                    // SQLi logic for sensitive headers
                    List<String> headersToAdd = new ArrayList<>();
                    
                    for (String sensitiveHeader : extension.getSensitiveHeaders()) {
                        // SQL injection payloads might use collaborator for out-of-band attacks (LOAD_FILE, xp_cmdshell, etc.)
                        String currentPayload = extension.getSqliPayload();
                        headersToAdd.add(sensitiveHeader + ": " + hostValue + currentPayload);
                    }
                    
                    headersToAdd.addAll(extension.getExtraHeaders());
                    
                    List<HttpHeader> newHeaders = addOrReplaceHeaders(originalRequest.headers(), headersToAdd);
                    HttpRequest modifiedRequest = originalRequest.withUpdatedHeaders(newHeaders);
                    
                    try {
                        long startTime = System.currentTimeMillis();
                        HttpRequestResponse response = api.http().sendRequest(modifiedRequest);
                        long endTime = System.currentTimeMillis();
                        long responseTime = endTime - startTime;
                        
                        if (responseTime >= extension.getSqliSleepTime() * 1000) {
                            api.logging().logToOutput("Context menu scan: Possible Blind SQL Injection detected! Response time: " + responseTime + " ms at URL: " + originalRequest.url());
                            auditIssueCreator.createSensitiveHeaderSqlIssue(response, responseTime);
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
            String url = selectedMessage.get().request().url();
            
            // Check if host is already excluded
            if (extension.isExcluded(url, host)) {
                api.logging().logToOutput("Host " + host + " is already excluded");
            } else {
                extension.addHostExclusion(host);
                extension.saveSettings();
                api.logging().logToOutput("Host " + host + " added to the exclusion list");
                
                // Refresh the exclusions table in the UI
                extension.getHeaderBangerTab().refreshExclusionsTable();
            }
        }
    }
    
    private void excludeUrlFromScans(ContextMenuEvent event) {
        Optional<HttpRequestResponse> selectedMessage = event.selectedRequestResponses().stream().findFirst();
        if (selectedMessage.isPresent()) {
            String url = selectedMessage.get().request().url();
            String host = selectedMessage.get().request().httpService().host();
            
            // Check if URL is already excluded
            if (extension.isExcluded(url, host)) {
                api.logging().logToOutput("URL " + url + " is already excluded");
            } else {
                extension.addUrlExclusion(url);
                extension.saveSettings();
                api.logging().logToOutput("URL " + url + " added to the exclusion list");
                
                // Refresh the exclusions table in the UI
                extension.getHeaderBangerTab().refreshExclusionsTable();
            }
        }
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
                
                // Special handling for extra headers - they should be governed by the allow duplicates setting
                boolean isExtraHeader = extension.getExtraHeaders().stream()
                        .anyMatch(eh -> eh.equalsIgnoreCase(headerToAdd));
                
                // For extra headers, check the allow duplicates setting
                if (isExtraHeader) {
                    if (!extension.isAllowDuplicateHeaders()) {
                        // If duplicates are not allowed, check if header already exists
                        boolean exists = originalHeaders.stream()
                                .anyMatch(h -> h.name().equalsIgnoreCase(headerName));
                        if (exists) {
                            continue; // Skip this header
                        }
                    }
                }
                
                newHeaders.add(HttpHeader.httpHeader(headerName, headerValue));
            }
        }
        
        return newHeaders;
    }
} 