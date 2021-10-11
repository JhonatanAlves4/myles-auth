package com.mylesauthapi.userApp;

import com.mylesauthapi.registration.token.ConfirmationToken;
import com.mylesauthapi.registration.token.ConfirmationTokenService;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Service
@AllArgsConstructor
public class UserAppService implements UserDetailsService {

    private final static String USER_NOT_FOUND_MSG = "User with email is not found";
    private final UserAppRepository userAppRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final ConfirmationTokenService confirmationTokenService;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userAppRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException(String.format(USER_NOT_FOUND_MSG, email)));
    }

    public List<UserApp> findAll() {
        return userAppRepository.findAll();
    }

    public String signUpUser(UserApp userApp) {
        boolean userExists = userAppRepository.findByEmail(userApp.getEmail()).isPresent();
        if (userExists) {
            throw new IllegalStateException("Email already taken");
        }

        String encodedPassword = bCryptPasswordEncoder.encode(userApp.getPassword());

        userApp.setPassword(encodedPassword);

        userAppRepository.save(userApp);

        String token = UUID.randomUUID().toString();
        // token confirmation account
        ConfirmationToken confirmationToken = new ConfirmationToken(
                token,
                LocalDateTime.now(),
                LocalDateTime.now().plusHours(4),
                userApp
        );

        userApp.setToken(token);
        confirmationTokenService.saveConfirmationToken(confirmationToken);

        return token;
    }

    public int enableUserApp(String email) {
        return userAppRepository.enableUserApp(email);
    }
}
