package computersystemsecurity;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingConstants;

import java.awt.Container;
import java.awt.Font;

public class RSAKeyPairGenerator extends JFrame {

    Container container;
    JLabel panelLabel, publicKeyLabel, privateKeyLabel;
    JTextArea publicKeyTextArea, privateKeyTextArea;
    JButton generateButton;
    JScrollPane publicScrollPane, privateScrollPane;


    public RSAKeyPairGenerator() {
        super("RSA Key Pair Generator");
        Initialize();
    }

    public void Initialize() {
        CreateComponents();
        AddContainer();
        SetBounds();
        AddActionListeners();

        this.setSize(400, 620);
        this.setLocationRelativeTo(null);
        this.setVisible(true);

        this.setResizable(true);
        this.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
    }

    public void CreateComponents() {
        container = getContentPane();
        container.setLayout(null);
        panelLabel = new JLabel("RSA Key Pair Generator");
        panelLabel.setFont(new Font("Courier", Font.BOLD, 20));
        panelLabel.setHorizontalAlignment(SwingConstants.CENTER);

        publicKeyLabel = new JLabel("Public Key:");
        publicKeyTextArea = new JTextArea();
        publicKeyTextArea.setLineWrap(true);
        publicKeyTextArea.setWrapStyleWord(true);
        publicScrollPane = new JScrollPane(publicKeyTextArea);

        privateKeyLabel = new JLabel("Private Key:");
        privateKeyTextArea = new JTextArea();
        privateKeyTextArea.setLineWrap(true);
        privateKeyTextArea.setWrapStyleWord(true);
        privateScrollPane = new JScrollPane(privateKeyTextArea);

        generateButton = new JButton("Generate Key Pair");

    }

    public void AddContainer() {
        container.add(publicScrollPane);
        container.add(privateScrollPane);
        container.add(panelLabel);
        container.add(publicKeyLabel);
        container.add(privateKeyLabel);
        container.add(generateButton);
    }

    public void SetBounds() {
        panelLabel.setBounds(0, 10, 400, 30);
        publicKeyLabel.setBounds(10, 50, 100, 30);
        publicScrollPane.setBounds(10, 80, 380, 200);
        privateKeyLabel.setBounds(10, 300, 100, 30);
        privateScrollPane.setBounds(10, 330, 380, 200);
        generateButton.setBounds(10, 540, 380, 40);
    }

    public void AddActionListeners() {

        generateButton.addActionListener(e -> {
            try {
                GenerateKeyPair();
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

    public void GenerateKeyPair() throws Exception {

        // RSA Anahtar Çifti Üretici oluştur
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048); // RSA için 2048 bitlik anahtar boyutunu kullan
        KeyPair pair = keyGen.generateKeyPair(); // Anahtar çiftini üret
        PrivateKey privateKey = pair.getPrivate(); // Özel anahtarı al
        PublicKey publicKey = pair.getPublic(); // Açık anahtarı al

        // Açık ve özel anahtarları JTextArea bileşenlerine hex formatında yazdır
        publicKeyTextArea.setText(bytesToHex(publicKey.getEncoded())); // Açık anahtarı hex formatında TextArea'ya yaz
        privateKeyTextArea.setText(bytesToHex(privateKey.getEncoded())); // Özel anahtarı hex formatında TextArea'ya yaz

    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02X", b));
        }
        return hex.toString();
    }

}
