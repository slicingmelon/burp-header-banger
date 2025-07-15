package slicingmelon.burpheaderbanger;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;

import java.util.*;
import java.util.concurrent.ScheduledExecutorService;

public class ProxyHandler implements ProxyRequestHandler, ProxyResponseHandler {
    private final BurpHeaderBanger extension;
    private final MontoyaApi api;
    private final ScheduledExecutorService scheduler;
    private final CollaboratorClient collaboratorClient;
    private final String collaboratorServerLocation;
    private final Map<String, Long> requestTimestamps;
    private final Map<String, PayloadCorrelation> payloadMap;
    private final AuditIssueBuilder auditIssueCreator;

    public ProxyHandler(BurpHeaderBanger extension, MontoyaApi api, ScheduledExecutorService scheduler,
                       CollaboratorClient collaboratorClient, String collaboratorServerLocation,
                       Map<String, Long> requestTimestamps, Map<String, PayloadCorrelation> payloadMap,
                       AuditIssueBuilder auditIssueCreator) {
        this.extension = extension;
        this.api = api;
        this.scheduler = scheduler;
        this.collaboratorClient = collaboratorClient;
        this.collaboratorServerLocation = collaboratorServerLocation;
        this.requestTimestamps = requestTimestamps;
        this.payloadMap = payloadMap;
        this.auditIssueCreator = auditIssueCreator;
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        if (!extension.isExtensionActive()) {
            return ProxyRequestReceivedAction.continueWith(interceptedRequest);
        }

        HttpRequest request = interceptedRequest;
        
        // Skip modification for requests going to the collaborator server
        if (collaboratorServerLocation != null && request.url().contains(collaboratorServerLocation)) {
            api.logging().logToOutput("Skipping collaborator request: " + request.url());
            return ProxyRequestReceivedAction.continueWith(interceptedRequest);
        }
        
        // Check if only processing in-scope items
        if (extension.isOnlyInScopeItems() && !api.scope().isInScope(request.url())) {
            return ProxyRequestReceivedAction.continueWith(interceptedRequest);
        }

        // Check if host should be skipped
        String host = request.httpService().host();
        if (extension.getSkipHosts().contains(host)) {
            return ProxyRequestReceivedAction.continueWith(interceptedRequest);
        }

        // Modify request headers
        HttpRequest modifiedRequest = modifyRequestHeaders(request);
        
        // Store timestamp for response time analysis
        String requestKey = request.url();
        requestTimestamps.put(requestKey, System.currentTimeMillis());
        
        // Limit dictionary size
        if (requestTimestamps.size() > BurpHeaderBanger.MAX_DICTIONARY_SIZE) {
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

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
        if (!extension.isExtensionActive()) {
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
        }

        // Skip responses from collaborator server
        if (collaboratorServerLocation != null && interceptedResponse.request().url().contains(collaboratorServerLocation)) {
            api.logging().logToOutput("Skipping collaborator response from: " + interceptedResponse.request().url());
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
        }

        // Process response for SQL injection detection
        if (extension.getAttackMode() == 1) {
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
        if (extension.getAttackMode() == 2) {
            return injectUniqueXssPayloads(request);
        } else {
            return injectSqlInjectionPayloads(request);
        }
    }

    private HttpRequest injectUniqueXssPayloads(HttpRequest request) {
        List<HttpHeader> modifiedHeaders = new ArrayList<>(request.headers());
        
        api.logging().logToOutput("Injecting XSS payloads for request: " + request.url());
        
        for (String headerName : extension.getHeaders()) {
            CollaboratorPayload collabPayload = collaboratorClient.generatePayload();
            String payloadDomain = collabPayload.toString();

            String finalPayload;
            if ("User-Agent".equalsIgnoreCase(headerName)) {
                finalPayload = extension.getBxssPayload().replace("{{collaborator}}", payloadDomain);
            } else if ("Referer".equalsIgnoreCase(headerName)) {
                String originalReferer = request.headerValue("Referer");
                if (originalReferer == null) originalReferer = request.url();
                finalPayload = originalReferer + extension.getBxssPayload().replace("{{collaborator}}", payloadDomain);
            } else {
                finalPayload = "1" + extension.getBxssPayload().replace("{{collaborator}}", payloadDomain);
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
        
        HttpRequest workingRequest = request.withUpdatedHeaders(modifiedHeaders);
        
        // Add extra headers using the proper API method
        for (String extraHeader : extension.getExtraHeaders()) {
            String[] parts = extraHeader.split(":", 2);
            if (parts.length == 2) {
                String headerName = parts[0].trim();
                String headerValue = parts[1].trim();
                
                if (extension.isOverwriteExtraHeaders()) {
                    workingRequest = workingRequest.withRemovedHeader(headerName);
                } else {
                    if (workingRequest.hasHeader(headerName)) {
                        continue;
                    }
                }
                
                workingRequest = workingRequest.withAddedHeader(headerName, headerValue);
            }
        }
        
        return workingRequest;
    }
    
    private HttpRequest injectSqlInjectionPayloads(HttpRequest request) {
        List<HttpHeader> modifiedHeaders = new ArrayList<>(request.headers());
        
        api.logging().logToOutput("Injecting SQL injection payloads for request: " + request.url());
        
        // Process ALL headers from the Headers list (both existing and non-existing)
        for (String headerName : extension.getHeaders()) {
            String finalPayload;
            
            if ("User-Agent".equalsIgnoreCase(headerName)) {
                // For User-Agent, use Mozilla prefix with payload
                finalPayload = "Mozilla/5.0" + extension.getSqliPayload();
            } else if ("Referer".equalsIgnoreCase(headerName)) {
                // For Referer, append payload to original value or use URL
                String originalReferer = request.headerValue("Referer");
                if (originalReferer == null) originalReferer = request.url();
                finalPayload = originalReferer + extension.getSqliPayload();
            } else {
                // For other headers, use "1" prefix with payload
                finalPayload = "1" + extension.getSqliPayload();
            }
            
            // Replace existing header or add new one
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
                api.logging().logToOutput("Added new header: " + headerName + " = " + finalPayload);
            } else {
                api.logging().logToOutput("Replaced existing header: " + headerName + " = " + finalPayload);
            }
        }
        
        HttpRequest workingRequest = request.withUpdatedHeaders(modifiedHeaders);
        
        // Add extra headers using the proper API method
        for (String extraHeader : extension.getExtraHeaders()) {
            String[] parts = extraHeader.split(":", 2);
            if (parts.length == 2) {
                String headerName = parts[0].trim();
                String headerValue = parts[1].trim();
                
                if (extension.isOverwriteExtraHeaders()) {
                    workingRequest = workingRequest.withRemovedHeader(headerName);
                } else {
                    if (workingRequest.hasHeader(headerName)) {
                        continue;
                    }
                }
                
                workingRequest = workingRequest.withAddedHeader(headerName, headerValue);
            }
        }
        
        return workingRequest;
    }

    private void processResponseForSqli(InterceptedResponse interceptedResponse) {
        // Check content type
        String contentType = getHeaderValue(interceptedResponse.headers(), "Content-Type");
        if (contentType != null) {
            String[] parts = contentType.split(";");
            if (parts.length > 0) {
                String mimeType = parts[0].trim().toLowerCase();
                if (BurpHeaderBanger.SKIP_CONTENT_TYPES.contains(mimeType)) {
                    return;
                }
            }
        }

        // Check response time
        String requestKey = interceptedResponse.request().url();
        Long startTime = requestTimestamps.get(requestKey);
        if (startTime != null) {
            long responseTime = System.currentTimeMillis() - startTime;
            requestTimestamps.remove(requestKey);
            
            if (responseTime >= extension.getSqliSleepTime() * 1000) {
                auditIssueCreator.createSqlInjectionIssue(interceptedResponse, responseTime);
            }
        }
    }

    private void processSensitiveHeadersScan(InterceptedResponse interceptedResponse) {
        HttpRequest originalRequest = interceptedResponse.initiatingRequest();
        
        api.logging().logToOutput("Processing sensitive headers scan for: " + originalRequest.url());
        
        // Get host value
        String hostValue = getHeaderValue(originalRequest.headers(), "Host");
        if (hostValue == null) {
            api.logging().logToOutput("No Host header found, skipping sensitive headers scan");
            return;
        }

        if (extension.getAttackMode() == 2) {
            // BXSS logic for sensitive headers
            List<HttpHeader> modifiedHeaders = new ArrayList<>(originalRequest.headers());
            
            for (String sensitiveHeader : extension.getSensitiveHeaders()) {
                CollaboratorPayload collabPayload = collaboratorClient.generatePayload();
                String payloadDomain = collabPayload.toString();
                String finalPayload = hostValue + extension.getBxssPayload().replace("{{collaborator}}", payloadDomain);
                
                // Store correlation for this payload
                PayloadCorrelation correlation = new PayloadCorrelation(originalRequest.url(), sensitiveHeader, originalRequest.method());
                payloadMap.put(payloadDomain, correlation);
                
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
            
            HttpRequest finalRequest = originalRequest.withUpdatedHeaders(addOrReplaceHeaders(modifiedHeaders, extension.getExtraHeaders()));
            api.http().sendRequest(finalRequest);
            return;
        }
        
        // SQL injection logic for sensitive headers
        List<String> headersToAdd = new ArrayList<>();
        
        // Add sensitive headers with payloads
        for (String sensitiveHeader : extension.getSensitiveHeaders()) {
            headersToAdd.add(sensitiveHeader + ": " + hostValue + extension.getSqliPayload());
        }

        // Add extra headers
        headersToAdd.addAll(extension.getExtraHeaders());

        List<HttpHeader> newHeaders = addOrReplaceHeaders(originalRequest.headers(), headersToAdd);
        HttpRequest modifiedRequest = originalRequest.withUpdatedHeaders(newHeaders);
        
        try {
            long startTime = System.currentTimeMillis();
            var response = api.http().sendRequest(modifiedRequest);
            long endTime = System.currentTimeMillis();
            long responseTime = endTime - startTime;

            if (responseTime >= extension.getSqliSleepTime() * 1000) {
                auditIssueCreator.createSensitiveHeaderSqlIssue(response, responseTime);
            }
        } catch (Exception e) {
            api.logging().logToError("Error sending sensitive headers request: " + e.getMessage());
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
                
                // Special handling for extra headers - they should be governed by the overwrite setting
                boolean isExtraHeader = extension.getExtraHeaders().stream()
                        .anyMatch(eh -> eh.equalsIgnoreCase(headerToAdd));
                
                // For extra headers, check the overwrite setting
                if (isExtraHeader) {
                    if (!extension.isOverwriteExtraHeaders()) {
                        // If overwrite is disabled, check if header already exists
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