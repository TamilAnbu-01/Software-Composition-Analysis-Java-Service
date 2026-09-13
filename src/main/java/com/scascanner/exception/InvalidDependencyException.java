package com.scascanner.exception;

/** A single dependency entry could not be normalized. Callers catch this per-item so one bad
 *  entry in a batch does not fail the whole scan - see ScanService. */
public class InvalidDependencyException extends RuntimeException {
    public InvalidDependencyException(String message) {
        super(message);
    }
}
