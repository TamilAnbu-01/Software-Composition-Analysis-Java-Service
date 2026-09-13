package com.scascanner.model;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.List;

public record ScanRequest(
        @NotBlank(message = "project must not be blank") String project,
        @NotNull(message = "dependencies must be present (use an empty list, not null)")
        @Valid List<DependencyInput> dependencies
) {
}
