package com.DenitMap.DMB_Security.Security;

import com.DenitMap.DMB_Security.Exceptions.BadRequestException;
import com.DenitMap.DMB_Security.Model.User;
import com.DenitMap.DMB_Security.Repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;


@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email).orElseThrow(()-> new BadRequestException("User was not Found"));

        return new org.springframework.security.core.userdetails.User(user.getEmail(), "N/A", List.of(()-> "ROLE_USER"));
    }

}