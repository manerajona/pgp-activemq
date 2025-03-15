package com.github.pgp;

import javax.jms.*;
import org.apache.activemq.ActiveMQConnectionFactory;
import org.bouncycastle.openpgp.PGPPublicKey;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;

import static com.github.pgp.Constants.*;

public class PGPMessagePublisher {
    public static void main(String[] args) {
        try {
            // Load the public key for encryption
            PGPPublicKey publicKey = PGPEncryptionUtils.readPublicKey(
                    new BufferedInputStream(new FileInputStream(PUBLIC_KEY_FILE))
            );

            // Sample clear text message
            String originalMessage = "Hello, this is a secret message!";

            // Encrypt the message (with integrity check and ASCII armor)
            byte[] encryptedData = PGPEncryptionUtils.encrypt(
                    originalMessage.getBytes(StandardCharsets.UTF_8),
                    publicKey,
                    true,  // withIntegrityCheck
                    true   // armor (ASCII)
            );
            System.out.println("Encrypted message:\n" + new String(encryptedData, StandardCharsets.UTF_8));

            // Setup ActiveMQ connection and send the encrypted message
            ActiveMQConnectionFactory connectionFactory = new ActiveMQConnectionFactory(ACTIVEMQ_BROKER_URL);
            Connection connection = connectionFactory.createConnection();
            connection.start();
            Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);
            Queue queue = session.createQueue(QUEUE_NAME);

            MessageProducer producer = session.createProducer(queue);

            BytesMessage message = session.createBytesMessage();
            message.writeBytes(encryptedData);
            producer.send(message);

            System.out.println("Message successfully sent to queue: " + QUEUE_NAME);

            // Clean up JMS resources
            producer.close();
            session.close();
            connection.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}