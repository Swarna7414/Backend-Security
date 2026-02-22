package com.DenitMap.DMB_Security.Service;

import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailService {
    private final JavaMailSender javaMailSender;

    public void sendMail(String toMail, String otp){

        SimpleMailMessage simpleMailMessage = new SimpleMailMessage();

        simpleMailMessage.setTo(toMail);
        simpleMailMessage.setSubject("Your Otp Code for Signup");
        simpleMailMessage.setText("your OTP is "+otp+" this will expire in 5 minutes");

        javaMailSender.send(simpleMailMessage);
    }
}