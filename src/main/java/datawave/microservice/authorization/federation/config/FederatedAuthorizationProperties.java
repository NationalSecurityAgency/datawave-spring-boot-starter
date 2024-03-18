package datawave.microservice.authorization.federation.config;

import java.util.concurrent.TimeUnit;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.PositiveOrZero;

public class FederatedAuthorizationProperties {
    private String federatedAuthorizationUri = "https://authorization:8443/authorization/v2";
    
    // true if federating to microservice, false if federating to webservice
    private boolean microservice = true;
    
    // max bytes to buffer for each rest call (-1 is unlimited)
    private int maxBytesToBuffer = -1;
    
    @PositiveOrZero
    private long listEffectiveAuthorizationsTimeout = TimeUnit.SECONDS.toMillis(30);
    
    @NotNull
    private TimeUnit listEffectiveAuthorizationsTimeUnit = TimeUnit.MILLISECONDS;
    
    @PositiveOrZero
    private long flushCachedCredentialsTimeout = TimeUnit.SECONDS.toMillis(30);
    
    @NotNull
    private TimeUnit flushCachedCredentialsTimeUnit = TimeUnit.MILLISECONDS;
    
    public String getFederatedAuthorizationUri() {
        return federatedAuthorizationUri;
    }
    
    public void setFederatedAuthorizationUri(String federatedAuthorizationUri) {
        this.federatedAuthorizationUri = federatedAuthorizationUri;
    }
    
    public boolean isMicroservice() {
        return microservice;
    }
    
    public void setMicroservice(boolean microservice) {
        this.microservice = microservice;
    }
    
    public int getMaxBytesToBuffer() {
        return maxBytesToBuffer;
    }
    
    public void setMaxBytesToBuffer(int maxBytesToBuffer) {
        this.maxBytesToBuffer = maxBytesToBuffer;
    }
    
    public long getListEffectiveAuthorizationsTimeout() {
        return listEffectiveAuthorizationsTimeout;
    }
    
    public long getListEffectiveAuthorizationsTimeoutMillis() {
        return listEffectiveAuthorizationsTimeUnit.toMillis(listEffectiveAuthorizationsTimeout);
    }
    
    public void setListEffectiveAuthorizationsTimeout(long listEffectiveAuthorizationsTimeout) {
        this.listEffectiveAuthorizationsTimeout = listEffectiveAuthorizationsTimeout;
    }
    
    public TimeUnit getListEffectiveAuthorizationsTimeUnit() {
        return listEffectiveAuthorizationsTimeUnit;
    }
    
    public void setListEffectiveAuthorizationsTimeUnit(TimeUnit listEffectiveAuthorizationsTimeUnit) {
        this.listEffectiveAuthorizationsTimeUnit = listEffectiveAuthorizationsTimeUnit;
    }
    
    public long getFlushCachedCredentialsTimeout() {
        return flushCachedCredentialsTimeout;
    }
    
    public long getFlushCachedCredentialsTimeoutMillis() {
        return flushCachedCredentialsTimeUnit.toMillis(flushCachedCredentialsTimeout);
    }
    
    public void setFlushCachedCredentialsTimeout(long flushCachedCredentialsTimeout) {
        this.flushCachedCredentialsTimeout = flushCachedCredentialsTimeout;
    }
    
    public TimeUnit getFlushCachedCredentialsTimeUnit() {
        return flushCachedCredentialsTimeUnit;
    }
    
    public void setFlushCachedCredentialsTimeUnit(TimeUnit flushCachedCredentialsTimeUnit) {
        this.flushCachedCredentialsTimeUnit = flushCachedCredentialsTimeUnit;
    }
}
