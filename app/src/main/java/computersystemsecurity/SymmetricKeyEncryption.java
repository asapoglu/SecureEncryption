package computersystemsecurity;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingConstants;

import java.awt.Container;
import java.awt.Font;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class SymmetricKeyEncryption extends JFrame {

    JButton generateButton;
    Container container;
    JLabel panelLabel, key128Label, key256Label, encryptedKey128Label, decryptedKey128Label, encryptedKey256Label,
            decryptedKey256Label;
    JTextArea key128TextArea, key256TextArea, encryptedKey128TextArea, decryptedKey128TextArea, encryptedKey256TextArea,
            decryptedKey256TextArea;
    JScrollPane key128ScrollPane, key256ScrollPane, encryptedKey128ScrollPane, decryptedKey128ScrollPane,
            encryptedKey256ScrollPane,
            decryptedKey256ScrollPane;

    public SymmetricKeyEncryption() {
        super("Symmetric Key Encryption");
        Initialize();
    }

    public void Initialize() {
        CreateComponents();
        AddContainer();
        SetBounds();
        AddActionListeners();

        this.setSize(400, 730);
        this.setLocationRelativeTo(null);
        this.setVisible(true);

        this.setResizable(true);
        this.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
    }

    private void CreateComponents() {
        container = getContentPane();
        container.setLayout(null);

        panelLabel = new JLabel("Symmetric Key Encryption");
        panelLabel.setFont(new Font("Courier", Font.BOLD, 20));
        panelLabel.setHorizontalAlignment(SwingConstants.CENTER);

        key128Label = new JLabel("Key 128:");
        key128TextArea = new JTextArea();
        key128TextArea.setLineWrap(true);
        key128TextArea.setWrapStyleWord(true);
        key128ScrollPane = new JScrollPane(key128TextArea);

        key256Label = new JLabel("Key 256:");
        key256TextArea = new JTextArea();
        key256TextArea.setLineWrap(true);
        key256TextArea.setWrapStyleWord(true);
        key256ScrollPane = new JScrollPane(key256TextArea);

        encryptedKey128Label = new JLabel("Encrypted Key 128:");
        encryptedKey128TextArea = new JTextArea();
        encryptedKey128TextArea.setLineWrap(true);
        encryptedKey128TextArea.setWrapStyleWord(true);
        encryptedKey128ScrollPane = new JScrollPane(encryptedKey128TextArea);

        decryptedKey128Label = new JLabel("Decrypted Key 128:");
        decryptedKey128TextArea = new JTextArea();
        decryptedKey128TextArea.setLineWrap(true);
        decryptedKey128TextArea.setWrapStyleWord(true);
        decryptedKey128ScrollPane = new JScrollPane(decryptedKey128TextArea);

        encryptedKey256Label = new JLabel("Encrypted Key 256:");
        encryptedKey256TextArea = new JTextArea();
        encryptedKey256TextArea.setLineWrap(true);
        encryptedKey256TextArea.setWrapStyleWord(true);
        encryptedKey256ScrollPane = new JScrollPane(encryptedKey256TextArea);

        decryptedKey256Label = new JLabel("Decrypted Key 256:");
        decryptedKey256TextArea = new JTextArea();
        decryptedKey256TextArea.setLineWrap(true);
        decryptedKey256TextArea.setWrapStyleWord(true);
        decryptedKey256ScrollPane = new JScrollPane(decryptedKey256TextArea);

        generateButton = new JButton("Generate Key");
    }

    private void AddContainer() {
        container.add(generateButton);
        container.add(panelLabel);
        container.add(key128Label);
        container.add(key128ScrollPane);
        container.add(key256Label);
        container.add(key256ScrollPane);
        container.add(encryptedKey128Label);
        container.add(encryptedKey128ScrollPane);
        container.add(decryptedKey128Label);
        container.add(decryptedKey128ScrollPane);
        container.add(encryptedKey256Label);
        container.add(encryptedKey256ScrollPane);
        container.add(decryptedKey256Label);
        container.add(decryptedKey256ScrollPane);

    }

    private void SetBounds() {
        panelLabel.setBounds(0, 10, 400, 30);
        key128Label.setBounds(10, 50, 100, 30);
        key128ScrollPane.setBounds(10, 80, 380, 60); 
        key256Label.setBounds(10, 150, 100, 30);
        key256ScrollPane.setBounds(10, 180, 380, 60); 
        encryptedKey128Label.setBounds(10, 250, 150, 30);
        encryptedKey128ScrollPane.setBounds(10, 280, 380, 60); 
        decryptedKey128Label.setBounds(10, 350, 150, 30);
        decryptedKey128ScrollPane.setBounds(10, 380, 380, 60); 
        encryptedKey256Label.setBounds(10, 450, 150, 30);
        encryptedKey256ScrollPane.setBounds(10, 480, 380, 60); 
        decryptedKey256Label.setBounds(10, 550, 150, 30);
        decryptedKey256ScrollPane.setBounds(10, 580, 380, 60); 
        generateButton.setBounds(10, 650, 380, 40);

    }

    private void AddActionListeners() {
        generateButton.addActionListener(e -> {
            try {
                GenerateKey();
            } catch (Exception e1) {
                e1.printStackTrace();
            }
        });
        addWindowListener(new java.awt.event.WindowAdapter() {
            @Override
            public void windowClosed(java.awt.event.WindowEvent windowEvent) {
                new App();
            }
        });
    }

    private void GenerateKey() throws Exception {
        // Simetrik Anahtarlar Üret
        KeyGenerator keyGen128 = KeyGenerator.getInstance("AES");
        keyGen128.init(128); // Anahtar boyutunu 128 bit olarak ayarla
        SecretKey key128 = keyGen128.generateKey(); // 128 bit AES anahtarı üret

        KeyGenerator keyGen256 = KeyGenerator.getInstance("AES");
        keyGen256.init(256); // Anahtar boyutunu 256 bit olarak ayarla
        SecretKey key256 = keyGen256.generateKey(); // 256 bit AES anahtarı üret

        System.out.println("128 bit Anahtar: " + bytesToHex(key128.getEncoded()));
        System.out.println("256 bit Anahtar: " + bytesToHex(key256.getEncoded()));

        key128TextArea.setText(bytesToHex(key128.getEncoded())); // 128 bit anahtarı TextArea'ya yaz
        key256TextArea.setText(bytesToHex(key256.getEncoded())); // 256 bit anahtarı TextArea'ya yaz

        // RSA Anahtar Çifti Üret
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048); // RSA için 2048 bit boyutunda anahtarlar ayarla
        KeyPair pair = keyGen.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate(); // Özel anahtar
        PublicKey publicKey = pair.getPublic(); // Açık anahtar

        // RSA ile Şifreleme ve Şifre Çözme
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey); // Şifreleme modunda başlat
        byte[] encryptedKey128 = cipher.doFinal(key128.getEncoded()); // 128 bit anahtarı şifrele
        byte[] encryptedKey256 = cipher.doFinal(key256.getEncoded()); // 256 bit anahtarı şifrele
        System.out.println("Şifrelenmiş 128 bit Anahtar: " + bytesToHex(encryptedKey128));
        System.out.println("Şifrelenmiş 256 bit Anahtar: " + bytesToHex(encryptedKey256));
        encryptedKey128TextArea.setText(bytesToHex(encryptedKey128)); // Şifrelenmiş 128 bit anahtarı TextArea'ya yaz
        encryptedKey256TextArea.setText(bytesToHex(encryptedKey256)); // Şifrelenmiş 256 bit anahtarı TextArea'ya yaz

        cipher.init(Cipher.DECRYPT_MODE, privateKey); // Şifre çözme modunda başlat
        byte[] decryptedKey128 = cipher.doFinal(encryptedKey128); // Şifrelenmiş 128 bit anahtarı çöz
        byte[] decryptedKey256 = cipher.doFinal(encryptedKey256); // Şifrelenmiş 256 bit anahtarı çöz
        System.out.println("Çözülmüş 128 bit Anahtar: " + bytesToHex(decryptedKey128));
        System.out.println("Çözülmüş 256 bit Anahtar: " + bytesToHex(decryptedKey256));
        decryptedKey128TextArea.setText(bytesToHex(decryptedKey128)); // Çözülmüş 128 bit anahtarı TextArea'ya yaz
        decryptedKey256TextArea.setText(bytesToHex(decryptedKey256)); // Çözülmüş 256 bit anahtarı TextArea'ya yaz

    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02X", b));
        }
        return hex.toString();
    }

}
