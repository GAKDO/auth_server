package com.gakdo.trace.auth.pairing.api;

import java.time.Instant;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.gakdo.trace.auth.pairing.application.PairingService;
import com.gakdo.trace.auth.pairing.application.PairingService.AgentToken;
import com.gakdo.trace.auth.pairing.application.PairingService.IssuedCode;

import com.gakdo.trace.auth.common.infra.NanoId;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

@RestController
@RequestMapping("/api/v1/auth/pairing-codes")
public class PairingController {

    private final PairingService pairingService;

    public PairingController(PairingService pairingService) {
        this.pairingService = pairingService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public PairingCodeResponse create(@Valid @RequestBody PairingCodeCreateRequest request) {
        IssuedCode issued = pairingService.create(request.rentalId(), request.checkpointId());
        return new PairingCodeResponse(issued.code(), issued.expiresAt());
    }

    @PostMapping("/exchange")
    public AgentTokenResponse exchange(@Valid @RequestBody PairingExchangeRequest request) {
        AgentToken result = pairingService.exchange(request.code());
        return new AgentTokenResponse(result.token().value(), "Bearer", result.token().expiresInSeconds(),
                result.rentalId(), result.checkpointId());
    }

    public record PairingCodeCreateRequest(@NotNull @Pattern(regexp = NanoId.PATTERN) String rentalId,
            @NotNull @Pattern(regexp = NanoId.PATTERN) String checkpointId) {
    }

    public record PairingCodeResponse(String code, Instant expiresAt) {
    }

    public record PairingExchangeRequest(@NotNull @Pattern(regexp = "^\\d{6}$") String code) {

        @Override
        public String toString() {
            return "PairingExchangeRequest[code=***]";
        }
    }

    public record AgentTokenResponse(String accessToken, String tokenType, long expiresIn, String rentalId,
                                     String checkpointId) {
    }
}
