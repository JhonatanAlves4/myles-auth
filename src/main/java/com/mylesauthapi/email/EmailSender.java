package com.mylesauthapi.email;

public interface EmailSender {
    void send(String to, String email);
}
