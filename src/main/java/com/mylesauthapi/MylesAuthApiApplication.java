package com.mylesauthapi;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

@SpringBootApplication
public class MylesAuthApiApplication {

	public static void main(String[] args) {
		SpringApplication.run(MylesAuthApiApplication.class, args);
	}

}
