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
    private final AuditIssueBuilder auditIssueCreator;

    public ScanCheck(BurpHeaderBanger extension, MontoyaApi api, ScheduledExecutorService scheduler,
                    CollaboratorClient collaboratorClient, AuditIssueBuilder auditIssueCreator) {
        this.extension = extension;
        this.api = api;
        this.scheduler = scheduler;
        this.collaboratorClient = collaboratorClient;
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
        api.logging().logToOutput("[CONTEXT_MENU] Menu items requested, event type: " + event.getClass().getSimpleName());
        api.logging().logToOutput("[CONTEXT_MENU] Selected request responses count: " + event.selectedRequestResponses().size());
        api.logging().logToOutput("[CONTEXT_MENU] Message editor request present: " + (event.messageEditorRequestResponse().isPresent()));
        
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
        
        api.logging().logToOutput("[CONTEXT_MENU] Returning " + menuItems.size() + " menu items");
        return menuItems;
    }

    private void scanSelectedRequest(ContextMenuEvent event) {
        Optional<HttpRequestResponse> selectedMessage = event.selectedRequestResponses().stream().findFirst();
        if (selectedMessage.isPresent()) {
            String url = selectedMessage.get().request().url();
            String host = selectedMessage.get().request().httpService().host();
            
            api.logging().logToOutput("Context menu scan initiated for: " + url);
            api.logging().logToOutput("Context menu scan: Checking exclusions for host: " + host + ", url: " + url);
            
            if (extension.isExcluded(url, host)) {
                api.logging().logToOutput("Header Banger: Skipping scan for excluded host/url: " + host + " / " + url);
                api.logging().logToOutput("Current exclusions list size: " + extension.getExclusions().size());
                for (Exclusion exclusion : extension.getExclusions()) {
                    api.logging().logToOutput("  - Exclusion: " + exclusion.toString());
                }
                return;
            }
            
            api.logging().logToOutput("Context menu scan: Host/URL not excluded, proceeding with scan");
            
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
                                
                                api.logging().logToOutput("Context menu: Using collaborator payload for sensitive header: " + sensitiveHeader + " with domain: " + payloadDomain);
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
                        
                        var response = api.http().sendRequest(finalRequest);
                        
                        // Check for 403 status code in context menu BXSS scan
                        if (response.response() != null && response.response().statusCode() == 403) {
                            String method = finalRequest.method();
                            String requestHost = finalRequest.httpService().host();
                            String pathQuery = finalRequest.path();
                            
                            Alert403Entry entry = new Alert403Entry(method, requestHost, pathQuery, 403, "Extensions");
                            extension.addAlert403Entry(entry);
                            
                            api.logging().logToOutput("[403_DETECTED] Context menu BXSS scan returned 403: " + method + " " + requestHost + pathQuery);
                        }
                        
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
                        
                        // Check for 403 status code in context menu SQL injection scan
                        if (response.response() != null && response.response().statusCode() == 403) {
                            String method = modifiedRequest.method();
                            String requestHost = modifiedRequest.httpService().host();
                            String pathQuery = modifiedRequest.path();
                            
                            Alert403Entry entry = new Alert403Entry(method, requestHost, pathQuery, 403, "Extensions");
                            extension.addAlert403Entry(entry);
                            
                            api.logging().logToOutput("[403_DETECTED] Context menu SQL injection scan returned 403: " + method + " " + requestHost + pathQuery);
                        }
                        
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
        api.logging().logToOutput("[CONTEXT_MENU] Exclude host action triggered");
        
        String host = null;
        String url = null;
        
        // Try to get the request from selected items first (proxy history)
        Optional<HttpRequestResponse> selectedMessage = event.selectedRequestResponses().stream().findFirst();
        if (selectedMessage.isPresent()) {
            host = selectedMessage.get().request().httpService().host();
            url = selectedMessage.get().request().url();
            api.logging().logToOutput("[CONTEXT_MENU] Got request from selected items");
        } else if (event.messageEditorRequestResponse().isPresent()) {
            // Try to get from message editor (request/response view)
            var messageEditorReqResp = event.messageEditorRequestResponse().get();
            host = messageEditorReqResp.requestResponse().request().httpService().host();
            url = messageEditorReqResp.requestResponse().request().url();
            api.logging().logToOutput("[CONTEXT_MENU] Got request from message editor");
        }
        
        if (host != null && url != null) {
            final String finalHost = host; // Make final for lambda
            api.logging().logToOutput("[CONTEXT_MENU] Attempting to exclude host: " + host + " from URL: " + url);
            
            // Check if host is already excluded
            if (extension.isExcluded(url, host)) {
                api.logging().logToOutput("[CONTEXT_MENU] Host " + host + " is already excluded");
                // Show user feedback
                SwingUtilities.invokeLater(() -> 
                    JOptionPane.showMessageDialog(null, "Host " + finalHost + " is already excluded from Header Banger scans.", 
                        "Already Excluded", JOptionPane.INFORMATION_MESSAGE));
            } else {
                api.logging().logToOutput("[CONTEXT_MENU] Adding host exclusion for: " + host);
                // addHostExclusion already handles saving settings and refreshing table
                extension.addHostExclusion(host);
                api.logging().logToOutput("[CONTEXT_MENU] Host " + host + " added to the exclusion list. Total exclusions: " + extension.getExclusions().size());
                
                // Show user feedback
                SwingUtilities.invokeLater(() -> 
                    JOptionPane.showMessageDialog(null, "Host " + finalHost + " has been excluded from Header Banger scans.", 
                        "Exclusion Added", JOptionPane.INFORMATION_MESSAGE));
            }
        } else {
            api.logging().logToOutput("[CONTEXT_MENU] No request found in either selected items or message editor");
        }
    }
    
    private void excludeUrlFromScans(ContextMenuEvent event) {
        api.logging().logToOutput("[CONTEXT_MENU] Exclude URL action triggered");
        
        String host = null;
        String url = null;
        
        // Try to get the request from selected items first (proxy history)
        Optional<HttpRequestResponse> selectedMessage = event.selectedRequestResponses().stream().findFirst();
        if (selectedMessage.isPresent()) {
            host = selectedMessage.get().request().httpService().host();
            url = selectedMessage.get().request().url();
            api.logging().logToOutput("[CONTEXT_MENU] Got request from selected items");
        } else if (event.messageEditorRequestResponse().isPresent()) {
            // Try to get from message editor (request/response view)
            var messageEditorReqResp = event.messageEditorRequestResponse().get();
            host = messageEditorReqResp.requestResponse().request().httpService().host();
            url = messageEditorReqResp.requestResponse().request().url();
            api.logging().logToOutput("[CONTEXT_MENU] Got request from message editor");
        }
        
        if (host != null && url != null) {
            final String finalUrl = url; // Make final for lambda
            api.logging().logToOutput("[CONTEXT_MENU] Attempting to exclude URL: " + url + " from host: " + host);
            
            // Check if URL is already excluded
            if (extension.isExcluded(url, host)) {
                api.logging().logToOutput("[CONTEXT_MENU] URL " + url + " is already excluded");
                // Show user feedback
                SwingUtilities.invokeLater(() -> 
                    JOptionPane.showMessageDialog(null, "URL " + finalUrl + " is already excluded from Header Banger scans.", 
                        "Already Excluded", JOptionPane.INFORMATION_MESSAGE));
            } else {
                api.logging().logToOutput("[CONTEXT_MENU] Adding URL exclusion for: " + url);
                // addUrlExclusion already handles saving settings and refreshing table
                extension.addUrlExclusion(url);
                api.logging().logToOutput("[CONTEXT_MENU] URL " + url + " added to the exclusion list. Total exclusions: " + extension.getExclusions().size());
                
                // Show user feedback
                SwingUtilities.invokeLater(() -> 
                    JOptionPane.showMessageDialog(null, "URL " + finalUrl + " has been excluded from Header Banger scans.", 
                        "Exclusion Added", JOptionPane.INFORMATION_MESSAGE));
            }
        } else {
            api.logging().logToOutput("[CONTEXT_MENU] No request found in either selected items or message editor");
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