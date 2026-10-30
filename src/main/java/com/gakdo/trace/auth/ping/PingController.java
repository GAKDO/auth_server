package com.gakdo.trace.auth.ping;

import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PingController {

    @GetMapping("/api/v1/auth/ping")
    public Map<String, String> ping() {
        return Map.of("service", "auth-server", "status", "ok");
    }
}
