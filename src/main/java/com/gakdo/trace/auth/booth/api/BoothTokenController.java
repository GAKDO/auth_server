package com.gakdo.trace.auth.booth.api;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.gakdo.trace.auth.booth.application.BoothTokenService;
import com.gakdo.trace.auth.booth.application.BoothTokenService.BoothToken;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@RestController
public class BoothTokenController {

    private final BoothTokenService boothTokenService;

    public BoothTokenController(BoothTokenService boothTokenService) {
        this.boothTokenService = boothTokenService;
    }

    @PostMapping("/api/v1/auth/booth/token")
    public BoothTokenResponse token(@Valid @RequestBody BoothTokenRequest request) {
        BoothToken result = boothTokenService.issue(request.clientId(), request.clientSecret());
        return new BoothTokenResponse(result.token().value(), "Bearer", result.token().expiresInSeconds(),
                result.boothId());
    }

    public record BoothTokenRequest(@NotBlank @Size(max = 64) String clientId, @NotBlank String clientSecret) {

        @Override
        public String toString() {
            return "BoothTokenRequest[clientId=" + clientId + ", clientSecret=***]";
        }
    }

    public record BoothTokenResponse(String accessToken, String tokenType, long expiresIn, String boothId) {
    }
}
