package com.study.sso.springsecurity.oauth2.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    @GetMapping("index")
    public Object index(Authentication authentication){
        return authentication;
    }

    @GetMapping("ceshi")
    public String ceshi()
    {
        return "ceshi";
    }
}
