package io.ont.error;

public enum AttestationError {
    SUCCESS(0),
    INVALID_PARAM(41001),
    ADDHASH_FAILED(41002),
    VERIFY_FAILED(41003),
    NODE_OUTSERVICE(41004),
    NO_AUTH(41005);

    private int code;

    AttestationError(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }
}
