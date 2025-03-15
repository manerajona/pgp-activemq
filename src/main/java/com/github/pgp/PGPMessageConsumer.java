package com.github.pgp;

import org.apache.activemq.ActiveMQConnectionFactory;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;

import javax.jms.*;
import java.io.BufferedInputStream;
import java.io.FileInputStream;

import static com.github.pgp.Constants.*;

public class PGPMessageConsumer {
    public static void main(String[] args) {
        try {
            // Load the secret key ring collection for decryption
            PGPSecretKeyRingCollection secretKeyRingCollection = PGPEncryptionUtils.readSecretKeyRingCollection(
                    new BufferedInputStream(new FileInputStream(PRIVATE_KEY_FILE))
            );

            // Setup ActiveMQ connection and receive the message
            ActiveMQConnectionFactory connectionFactory = new ActiveMQConnectionFactory(ACTIVEMQ_BROKER_URL);
            Connection connection = connectionFactory.createConnection();
            connection.start();
            Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);
            Queue queue = session.createQueue(QUEUE_NAME);

            MessageConsumer consumer = session.createConsumer(queue);

            Message message;
            while ((message = consumer.receive(5000)) == null) {
                System.out.println("No message received, will try again in 5 sec.");
            }
            if (message instanceof BytesMessage bytesMessage) {
                byte[] encryptedMessage = new byte[(int) bytesMessage.getBodyLength()];
                bytesMessage.readBytes(encryptedMessage);

                // Decrypt the message
                String decryptedMessage = PGPEncryptionUtils.decrypt(
                        encryptedMessage,
                        secretKeyRingCollection,
                        PRIVATE_KEY_PASSPHRASE.toCharArray()
                );
                System.out.println("Decrypted Message: " + decryptedMessage);
            }

            // Clean up JMS resources
            consumer.close();
            session.close();
            connection.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
