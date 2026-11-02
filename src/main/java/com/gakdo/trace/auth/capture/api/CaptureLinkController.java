package com.gakdo.trace.auth.capture.api;

import java.time.Instant;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.gakdo.trace.auth.capture.application.CaptureLinkService;
import com.gakdo.trace.auth.capture.application.CaptureLinkService.CaptureToken;
import com.gakdo.trace.auth.capture.application.CaptureLinkService.IssuedLink;

import com.gakdo.trace.auth.common.infra.NanoId;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

@RestController
@RequestMapping("/api/v1/auth/capture-links")
public class CaptureLinkController {

    private final CaptureLinkService captureLinkService;

    public CaptureLinkController(CaptureLinkService captureLinkService) {
        this.captureLinkService = captureLinkService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public CaptureLinkResponse create(@Valid @RequestBody CaptureLinkCreateRequest request) {
        IssuedLink link = captureLinkService.create(request.rentalId(), request.checkpointId());
        return new CaptureLinkResponse(link.url(), link.expiresAt());
    }

    @PostMapping("/exchange")
    public CaptureTokenResponse exchange(@AuthenticationPrincipal Jwt jwt,
                                         @Valid @RequestBody CaptureLinkExchangeRequest request) {
        CaptureToken result = captureLinkService.exchange(jwt.getSubject(), request.token());
        return new CaptureTokenResponse(result.token().value(), "Bearer", result.token().expiresInSeconds(),
                result.rentalId(), result.checkpointId());
    }

    public record CaptureLinkCreateRequest(@NotNull @Pattern(regexp = NanoId.PATTERN) String rentalId,
            @NotNull @Pattern(regexp = NanoId.PATTERN) String checkpointId) {
    }

    public record CaptureLinkResponse(String url, Instant expiresAt) {
    }

    public record CaptureLinkExchangeRequest(@NotNull @Size(min = 16, max = 256) String token) {

        @Override
        public String toString() {
            return "CaptureLinkExchangeRequest[token=***]";
        }
    }

    public record CaptureTokenResponse(String accessToken, String tokenType, long expiresIn, String rentalId,
                                       String checkpointId) {
    }
}
