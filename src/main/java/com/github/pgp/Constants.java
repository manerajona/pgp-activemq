package com.github.pgp;

public class Constants {

    static final String ACTIVEMQ_BROKER_URL = "tcp://localhost:61616";
    static final String QUEUE_NAME = "PGP_QUEUE";
    static final String PUBLIC_KEY_FILE = "public.asc";
    static final String PRIVATE_KEY_FILE = "private.asc";
    static final String PRIVATE_KEY_PASSPHRASE = "changeit";
    static final String PRIVATE_KEY_IDENTITY = "user@example.com";

    private Constants() {
    }
}
