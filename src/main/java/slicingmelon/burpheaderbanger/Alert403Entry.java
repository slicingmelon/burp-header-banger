package slicingmelon.burpheaderbanger;

public class Alert403Entry {
    private final String method;
    private final String host;
    private final String pathQuery;
    private final int statusCode;
    private final String source;
    private final long timestamp;
    
    public Alert403Entry(String method, String host, String pathQuery, int statusCode, String source) {
        this.method = method;
        this.host = host;
        this.pathQuery = pathQuery;
        this.statusCode = statusCode;
        this.source = source;
        this.timestamp = System.currentTimeMillis();
    }
    
    public String getMethod() {
        return method;
    }
    
    public String getHost() {
        return host;
    }
    
    public String getPathQuery() {
        return pathQuery;
    }
    
    public int getStatusCode() {
        return statusCode;
    }
    
    public String getSource() {
        return source;
    }
    
    public long getTimestamp() {
        return timestamp;
    }
    
    public String getUrl() {
        return "https://" + host + pathQuery;
    }
    
    @Override
    public String toString() {
        return String.format("%s %s %s %d %s", method, host, pathQuery, statusCode, source);
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        Alert403Entry that = (Alert403Entry) obj;
        return statusCode == that.statusCode &&
               method.equals(that.method) &&
               host.equals(that.host) &&
               pathQuery.equals(that.pathQuery) &&
               source.equals(that.source);
    }
    
    @Override
    public int hashCode() {
        return java.util.Objects.hash(method, host, pathQuery, statusCode, source);
    }
} 