package com.DenitMap.DMB_Security.Model;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "auth_accounts", uniqueConstraints = {
        @UniqueConstraint(columnNames = {"provider", "providerUserId"}),
        @UniqueConstraint(columnNames = {"user_id","provider"})
})
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthAccount {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AuthProvider provider;

    @Column(nullable = true, length = 200)
    private String providerUserId;

    @Column(nullable = true, length = 200)
    private String passwordHash;

    @Column(nullable = false)
    private Instant createdAt;
}