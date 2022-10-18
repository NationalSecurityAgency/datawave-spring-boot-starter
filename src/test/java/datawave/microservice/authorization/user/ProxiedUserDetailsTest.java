package datawave.microservice.authorization.user;

import com.google.common.collect.Lists;
import datawave.security.authorization.DatawaveUser;
import datawave.security.authorization.DatawaveUser.UserType;
import datawave.security.authorization.SubjectIssuerDNPair;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class ProxiedUserDetailsTest {
    
    private DatawaveUser finalConnectionServer;
    private DatawaveUser server1;
    private DatawaveUser server2;
    private DatawaveUser server3;
    private DatawaveUser user;
    
    final private String finalConnectionServerSubjectDn = "cn=finalconnectionserver";
    final private String server1SubjectDn = "cn=server1";
    final private String server2SubjectDn = "cn=server2";
    final private String server3SubjectDn = "cn=server3";
    final private String userSubjectDn = "cn=user";
    final private String issuerDn = "cn=certificateissuer";
    
    @BeforeEach
    public void setUp() throws Exception {
        long now = System.currentTimeMillis();
        SubjectIssuerDNPair finalConnectionServerDn = SubjectIssuerDNPair.of(finalConnectionServerSubjectDn, issuerDn);
        SubjectIssuerDNPair server1Dn = SubjectIssuerDNPair.of(server1SubjectDn, issuerDn);
        SubjectIssuerDNPair server2Dn = SubjectIssuerDNPair.of(server2SubjectDn, issuerDn);
        SubjectIssuerDNPair server3Dn = SubjectIssuerDNPair.of(server3SubjectDn, issuerDn);
        SubjectIssuerDNPair userDn = SubjectIssuerDNPair.of(userSubjectDn, issuerDn);
        finalConnectionServer = new DatawaveUser(finalConnectionServerDn, UserType.SERVER, null, null, null, now);
        server1 = new DatawaveUser(server1Dn, UserType.SERVER, null, null, null, now);
        server2 = new DatawaveUser(server2Dn, UserType.SERVER, null, null, null, now);
        server3 = new DatawaveUser(server3Dn, UserType.SERVER, null, null, null, now);
        user = new DatawaveUser(userDn, UserType.USER, null, null, null, now);
    }
    
    @Test
    public void PrimaryUserTest() {
        long now = System.currentTimeMillis();
        // direct call from a server
        ProxiedUserDetails proxiedUserDetails = new ProxiedUserDetails(Lists.newArrayList(finalConnectionServer), now);
        Assertions.assertEquals(finalConnectionServerSubjectDn, proxiedUserDetails.getPrimaryUser().getDn().subjectDN());
        
        // direct call from a user
        proxiedUserDetails = new ProxiedUserDetails(Lists.newArrayList(user), now);
        Assertions.assertEquals(userSubjectDn, proxiedUserDetails.getPrimaryUser().getDn().subjectDN());
        
        // call from finalConnectionServer proxying initial caller server1
        proxiedUserDetails = new ProxiedUserDetails(Lists.newArrayList(server1, finalConnectionServer), now);
        Assertions.assertEquals(server1SubjectDn, proxiedUserDetails.getPrimaryUser().getDn().subjectDN());
        
        // call from finalConnectionServer proxying initial caller server1 through server2
        proxiedUserDetails = new ProxiedUserDetails(Lists.newArrayList(server1, server2, finalConnectionServer), now);
        Assertions.assertEquals(server1SubjectDn, proxiedUserDetails.getPrimaryUser().getDn().subjectDN());
        
        // call from finalConnectionServer proxying initial caller server1 through server2 and server3
        proxiedUserDetails = new ProxiedUserDetails(Lists.newArrayList(server1, server2, server3, finalConnectionServer), now);
        Assertions.assertEquals(server1SubjectDn, proxiedUserDetails.getPrimaryUser().getDn().subjectDN());
        
        // these tests are for case where a UserType.USER appears anywhere in the proxiedUsers collection
        proxiedUserDetails = new ProxiedUserDetails(Lists.newArrayList(user, server1, server2, server3), now);
        Assertions.assertEquals(userSubjectDn, proxiedUserDetails.getPrimaryUser().getDn().subjectDN());
        
        proxiedUserDetails = new ProxiedUserDetails(Lists.newArrayList(server1, user, server2, server3), now);
        Assertions.assertEquals(userSubjectDn, proxiedUserDetails.getPrimaryUser().getDn().subjectDN());
        
        proxiedUserDetails = new ProxiedUserDetails(Lists.newArrayList(server1, server2, user, server3), now);
        Assertions.assertEquals(userSubjectDn, proxiedUserDetails.getPrimaryUser().getDn().subjectDN());
        
        proxiedUserDetails = new ProxiedUserDetails(Lists.newArrayList(server1, server2, server3, user), now);
        Assertions.assertEquals(userSubjectDn, proxiedUserDetails.getPrimaryUser().getDn().subjectDN());
    }
    
    @Test
    public void OrderProxiedUsers() {
        
        long now = System.currentTimeMillis();
        
        // call from finalServer
        Assertions.assertEquals(Lists.newArrayList(finalConnectionServer), ProxiedUserDetails.orderProxiedUsers(Lists.newArrayList(finalConnectionServer)));
        
        // call from finalServer proxying initial caller server1
        Assertions.assertEquals(Lists.newArrayList(server1, finalConnectionServer),
                        ProxiedUserDetails.orderProxiedUsers(Lists.newArrayList(server1, finalConnectionServer)));
        
        // call from finalServer proxying initial caller server1 through server2
        Assertions.assertEquals(Lists.newArrayList(server1, server2, finalConnectionServer),
                        ProxiedUserDetails.orderProxiedUsers(Lists.newArrayList(server1, server2, finalConnectionServer)));
        
        // call from finalServer proxying initial caller server1 through server2 and server3
        Assertions.assertEquals(Lists.newArrayList(server1, server2, server3, finalConnectionServer),
                        ProxiedUserDetails.orderProxiedUsers(Lists.newArrayList(server1, server2, server3, finalConnectionServer)));
        
        // these tests are for cases where a UserType.USER appears anywhere in the proxiedUsers collection
        
        Assertions.assertEquals(Lists.newArrayList(user, server1, server2, server3),
                        ProxiedUserDetails.orderProxiedUsers(Lists.newArrayList(user, server1, server2, server3)));
        
        Assertions.assertEquals(Lists.newArrayList(user, server1, server2, server3),
                        ProxiedUserDetails.orderProxiedUsers(Lists.newArrayList(server1, user, server2, server3)));
        
        Assertions.assertEquals(Lists.newArrayList(user, server1, server2, server3),
                        ProxiedUserDetails.orderProxiedUsers(Lists.newArrayList(server1, server2, user, server3)));
        
        // this case would be very odd -- call from user proxying initial caller server1 through server2 through server3
        Assertions.assertEquals(Lists.newArrayList(user, server1, server2, server3),
                        ProxiedUserDetails.orderProxiedUsers(Lists.newArrayList(server1, server2, server3, user)));
    }
    
    @Test
    public void DuplicateUserPreserved() {
        // check that duplicate users are preserved
        ProxiedUserDetails dp = new ProxiedUserDetails(Lists.newArrayList(server1, server2, server1), System.currentTimeMillis());
        Assertions.assertEquals(3, dp.getProxiedUsers().size());
        Assertions.assertEquals(server1, dp.getProxiedUsers().stream().findFirst().get());
        Assertions.assertEquals(server2, dp.getProxiedUsers().stream().skip(1).findFirst().get());
        Assertions.assertEquals(server1, dp.getProxiedUsers().stream().skip(2).findFirst().get());
    }
}
