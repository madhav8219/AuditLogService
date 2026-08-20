package com.auditlog.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Map;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RedactionResponse {
    private Long id;
    private Map<String, Object> payload;
    private Map<String, Object> redaction;
    private String hash;
}
