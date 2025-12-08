package com.jwt.dto;

import lombok.Getter;

@Getter
public class AuthResponse {
    private String token;
    
    public AuthResponse() {
    }

	public AuthResponse(String token) {
		super();
		this.token = token;
	}
    
    
}