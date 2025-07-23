package slicingmelon.burpheaderbanger;

import java.util.regex.Pattern;

public class Exclusion {
    private boolean enabled;
    private String pattern;
    private transient Pattern compiledPattern;
    
    public Exclusion(boolean enabled, String pattern) {
        this.enabled = enabled;
        this.pattern = pattern;
        compilePattern();
    }
    
    public Exclusion() {
        this(true, "");
    }
    
    public boolean isEnabled() {
        return enabled;
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    public String getPattern() {
        return pattern;
    }
    
    public void setPattern(String pattern) {
        this.pattern = pattern;
        compilePattern();
    }
    
    private void compilePattern() {
        if (pattern != null && !pattern.isEmpty()) {
            try {
                this.compiledPattern = Pattern.compile(pattern);
            } catch (Exception e) {
                this.compiledPattern = null;
            }
        } else {
            this.compiledPattern = null;
        }
    }
    
    public boolean matches(String input) {
        if (!enabled || pattern == null || pattern.isEmpty() || input == null) {
            return false;
        }
        
        if (compiledPattern == null) {
            return false;
        }
        return compiledPattern.matcher(input).find();
    }
    
    @Override
    public String toString() {
        return (enabled ? "ENABLED" : "DISABLED") + " " + pattern + " (regex)";
    }
    
    // For JSON serialization
    public String toJson() {
        return String.format("{\"enabled\":%s,\"pattern\":\"%s\"}", 
                enabled, pattern.replace("\"", "\\\""));
    }
    
    // For JSON deserialization
    public static Exclusion fromJson(String json) {
        try {
            json = json.trim();
            if (json.startsWith("{") && json.endsWith("}")) {
                json = json.substring(1, json.length() - 1);
            }
            
            boolean enabled = true;
            String pattern = "";
            
            String[] parts = json.split(",");
            for (String part : parts) {
                part = part.trim();
                if (part.startsWith("\"enabled\":")) {
                    enabled = Boolean.parseBoolean(part.substring(10));
                } else if (part.startsWith("\"pattern\":\"")) {
                    pattern = part.substring(11, part.length() - 1).replace("\\\"", "\"");
                }
            }
            
            return new Exclusion(enabled, pattern);
        } catch (Exception e) {
            return new Exclusion();
        }
    }
} 