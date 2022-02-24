package datawave.microservice.authorization.user;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import datawave.security.authorization.DatawaveUser;
import datawave.security.authorization.DatawaveUser.UserType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * A {@link UserDetails} that represents a set of proxied users. For example, this proxied user could represent a GUI server acting on behalf of a user. The GUI
 * server user represents the entity that made the call to us, but the user is the actual end user.
 */
@XmlRootElement
public class ProxiedUserDetails implements UserDetails {
    private String username;
    private List<DatawaveUser> proxiedUsers = new ArrayList<>();
    private List<SimpleGrantedAuthority> roles;
    private long creationTime;
    
    @JsonCreator
    public ProxiedUserDetails(@JsonProperty("proxiedUsers") Collection<? extends DatawaveUser> proxiedUsers, @JsonProperty("creationTime") long creationTime) {
        this.proxiedUsers.addAll(proxiedUsers);
        this.username = ProxiedUserDetails.orderProxiedUsers(this.proxiedUsers).stream().map(DatawaveUser::getName).collect(Collectors.joining(" -> "));
        this.roles = getPrimaryUser().getRoles().stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        this.creationTime = creationTime;
    }
    
    public Collection<? extends DatawaveUser> getProxiedUsers() {
        return Collections.unmodifiableList(proxiedUsers);
    }
    
    /**
     * Gets the {@link DatawaveUser} that represents the primary user in this ProxiedUserDetails. If there is only one DatawaveUser, then it is the primaryUser.
     * If there is more than one DatawaveUser, then the first (and presumably only) DatawaveUser whose {@link DatawaveUser#getUserType()} is
     * {@link UserType#USER} is the primary user. If no such DatawaveUser is present, then the second principal in the list is returned as the primary user.
     * This will be the first entity in the X-ProxiedEntitiesChain which should be the server that originated the request.
     *
     * @return The {@link DatawaveUser} that represents the primary user in the list of proxied users
     */
    @JsonIgnore
    public DatawaveUser getPrimaryUser() {
        return ProxiedUserDetails.findPrimaryUser(this.proxiedUsers);
    }
    
    static protected DatawaveUser findPrimaryUser(List<DatawaveUser> datawaveUsers) {
        if (datawaveUsers.size() <= 1) {
            return datawaveUsers.get(0);
        } else {
            DatawaveUser secondInOrder = datawaveUsers.get(1);
            return datawaveUsers.stream().filter(u -> u.getUserType() == UserType.USER).findFirst().orElse(secondInOrder);
        }
    }
    
    /*
     * The purpose here is to return a List of DatawaveUsers where the original caller is first followed by any entities in X-ProxiedEntitiesChain in the order
     * that they were traversed and ending with the entity that made the final call. The List that is passed is not modified. This method makes the following
     * assumptions about the List that is passed to ths method: 1) The first element is the one that made the final call 2) Additional elements (if any) are
     * from X-ProxiedEntitiesChain in chronological order of the calls
     */
    static protected List<DatawaveUser> orderProxiedUsers(List<DatawaveUser> datawaveUsers) {
        DatawaveUser primary = ProxiedUserDetails.findPrimaryUser(datawaveUsers);
        List<DatawaveUser> users = new ArrayList<>();
        users.add(primary);
        if (datawaveUsers.size() > 1) {
            // @formatter:off
            // Skipping first user because if it is UserType.USER, it is the primary
            // and already added.  If it is UserType.Server, then it will be added at the end
            users.addAll(datawaveUsers.stream()
                    .skip(1)
                    .filter(u -> u != primary)
                    .collect(Collectors.toList()));
            // @formatter:on
            DatawaveUser first = datawaveUsers.get(0);
            if (!users.contains(first)) {
                users.add(first);
            }
        }
        return users;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        
        ProxiedUserDetails that = (ProxiedUserDetails) o;
        
        if (!username.equals(that.username))
            return false;
        return proxiedUsers.equals(that.proxiedUsers);
    }
    
    @Override
    public int hashCode() {
        int result = username.hashCode();
        result = 31 * result + proxiedUsers.hashCode();
        return result;
    }
    
    @Override
    public String toString() {
        // @formatter:off
        return "ProxiedUserDetails{" +
                "username='" + username + '\'' +
                ", proxiedUsers=" + ProxiedUserDetails.orderProxiedUsers(proxiedUsers) +
                '}';
        // @formatter:on
    }
    
    @Override
    @JsonIgnore
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles;
    }
    
    @Override
    @JsonIgnore
    public String getPassword() {
        return "";
    }
    
    @Override
    @JsonIgnore
    public String getUsername() {
        return username;
    }
    
    @Override
    @JsonIgnore
    public boolean isAccountNonExpired() {
        return true;
    }
    
    @Override
    @JsonIgnore
    public boolean isAccountNonLocked() {
        return true;
    }
    
    @Override
    @JsonIgnore
    public boolean isCredentialsNonExpired() {
        return true;
    }
    
    @Override
    @JsonIgnore
    public boolean isEnabled() {
        return true;
    }
    
    public long getCreationTime() {
        return creationTime;
    }
}
