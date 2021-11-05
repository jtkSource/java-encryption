package com.jtk.crypto.exception;

public class JTKEncyptionException extends RuntimeException {
    public JTKEncyptionException(String msg) {
        super(msg);
    }

    public JTKEncyptionException(String msg, Throwable t) {
        super(msg, t);
    }
}
