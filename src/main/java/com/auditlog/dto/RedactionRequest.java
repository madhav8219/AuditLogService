package com.auditlog.dto;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RedactionRequest {
    @NotNull(message = "fields must be provided")
    private List<@jakarta.validation.constraints.NotBlank(message = "field names must not be blank") String> fields;
}
