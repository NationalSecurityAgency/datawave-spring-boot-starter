package datawave.microservice.config.security;

import datawave.microservice.authorization.config.DatawaveSecurityProperties;
import datawave.security.authorization.SubjectIssuerDNPair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.Nullable;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

public class AllowedCallersFilter extends OncePerRequestFilter {
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final DatawaveSecurityProperties securityProperties;
    
    public AllowedCallersFilter(DatawaveSecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain)
                    throws ServletException, IOException {
        if (securityProperties.isEnforceAllowedCallers()) {
            // Extract the client certificate, and if one is provided, validate that the caller is allowed to talk to us.
            X509Certificate cert = extractClientCertificate(httpServletRequest);
            if (cert != null) {
                final SubjectIssuerDNPair dnPair = SubjectIssuerDNPair.of(cert.getSubjectX500Principal().getName(), cert.getIssuerX500Principal().getName());
                final String callerName = dnPair.toString();
                final List<String> allowedCallers = securityProperties.getAllowedCallers();
                if (!allowedCallers.contains(callerName)) {
                    logger.warn("Not allowing {} to talk since it is not in the list of allowed callers {}", dnPair, allowedCallers);
                    httpServletResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "403 Forbidden: User not in the list of allowed users");
                    return;
                }
            }
        }
        // Continue the chain to handle any other filters
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
    
    @Nullable
    private X509Certificate extractClientCertificate(HttpServletRequest request) {
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
        
        if (certs != null && certs.length > 0) {
            if (logger.isDebugEnabled()) {
                logger.debug("X.509 client authentication certificate:" + certs[0]);
            }
            
            return certs[0];
        }
        
        if (logger.isDebugEnabled()) {
            logger.debug("No client certificate found in request.");
        }
        
        return null;
    }
}
