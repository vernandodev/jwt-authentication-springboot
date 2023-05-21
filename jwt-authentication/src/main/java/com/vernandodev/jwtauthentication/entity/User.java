package com.vernandodev.jwtauthentication.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotEmpty;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data
@Builder
@NoArgsConstructor // will generate a constructor with no parameters
@AllArgsConstructor // generates a constructor with 1 parameter for each field in your class
@Entity
@Table(name = "tbl_user")
public class User implements UserDetails {
    @Id
    @GeneratedValue
    private Integer id;
    @NotEmpty(message="firstName is required")
    @Column(name="first_name")
    private String firstName;
    @NotEmpty(message="lastName is required")
    @Column(name="last_name")
    private String lastName;
    @NotEmpty(message="email is required")
    @Column(name="email")
    private String email;
    @NotEmpty(message="password is required")
    @Column(name="password")
    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name())); // return list of roles
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
