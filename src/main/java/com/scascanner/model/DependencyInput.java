package com.scascanner.model;

/**
 * Raw dependency exactly as it arrives over the wire. Ecosystem is kept as a String here
 * (not the enum) so an unrecognized ecosystem is a validation error we can report per-item,
 * not a JSON deserialization exception that kills the whole request.
 */
public record DependencyInput(String ecosystem, String group, String name, String version) {
}
