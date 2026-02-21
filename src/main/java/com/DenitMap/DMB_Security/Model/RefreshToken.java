package com.DenitMap.DMB_Security.Model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Entity
@Table(name = "refresh_tokens")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(nullable = false, unique = true, length = 900)
    private String token;

    @Column(nullable = false)
    private Instant expiresAt;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    private User user;

}