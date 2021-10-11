package com.mylesauthapi.registration;

import com.mylesauthapi.userApp.UserApp;
import com.mylesauthapi.userApp.UserAppService;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping(path = "api/v1/registration")
@AllArgsConstructor
public class RegistrationController {

    private final RegistrationService registrationService;
    private UserAppService userAppService;

    @GetMapping(value = "/", produces = "application/json")
    public List<UserApp> findAll() {
        return userAppService.findAll();
    }

    @PostMapping
    public String registrer(@RequestBody RegistrationRequest request) {
        return registrationService.register(request);
    }

    @GetMapping(path = "confirm")
    public String confirm(@RequestParam("token") String token) {
        return registrationService.confirmToken(token);
    }

}
