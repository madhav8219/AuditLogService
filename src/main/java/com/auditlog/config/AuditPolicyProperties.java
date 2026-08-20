package com.auditlog.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
@ConfigurationProperties(prefix = "audit.policy")
public class AuditPolicyProperties {

    private Retention retention = new Retention();
    private Redaction redaction = new Redaction();

    public Retention getRetention() {
        return retention;
    }

    public void setRetention(Retention retention) {
        this.retention = retention == null ? new Retention() : retention;
    }

    public Redaction getRedaction() {
        return redaction;
    }

    public void setRedaction(Redaction redaction) {
        this.redaction = redaction == null ? new Redaction() : redaction;
    }

    public static class Retention {
        private long defaultDays = 30L;

        public long getDefaultDays() {
            return defaultDays;
        }

        public void setDefaultDays(long defaultDays) {
            this.defaultDays = defaultDays;
        }
    }

    public static class Redaction {
        private List<String> sensitiveFields = new ArrayList<>(List.of(
                "accountNumber",
                "ssn",
                "personalId",
                "customerId",
                "email",
                "password",
                "token",
                "secret"
        ));

        public List<String> getSensitiveFields() {
            return sensitiveFields;
        }

        public void setSensitiveFields(List<String> sensitiveFields) {
            this.sensitiveFields = sensitiveFields == null ? new ArrayList<>() : sensitiveFields;
        }
    }
}
