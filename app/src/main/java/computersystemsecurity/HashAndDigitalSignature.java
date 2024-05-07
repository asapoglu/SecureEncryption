package computersystemsecurity;

import java.awt.Container;
import java.awt.Font;
import java.awt.ScrollPane;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JRadioButton;
import javax.swing.JTextArea;
import javax.swing.SwingConstants;

public class HashAndDigitalSignature extends JFrame {

    Container container;
    JTextArea longMessage, hashTextArea, digitalSignatureTextArea;
    ScrollPane longMessageScrollPane, hashScrollPane, digitalSignatureScrollPane;
    JLabel panelLabel, longMessageLabel, hashLabel, digitalSignatureLabel;
    JButton generateButton;
    JRadioButton verifiedButon;

    public HashAndDigitalSignature() {
        super("Hash and Digital Signature");
        Initialize();
    }

    public void Initialize() {
        CreateComponents();
        AddContainer();
        SetBounds();
        AddActionListeners();

        this.setSize(400, 580);
        this.setLocationRelativeTo(null);
        this.setVisible(true);

        this.setResizable(true);
        this.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
    }

    public void CreateComponents() {
        container = getContentPane();
        container.setLayout(null);

        panelLabel = new JLabel("Hash and Digital Signature");
        panelLabel.setFont(new Font("Courier", Font.BOLD, 20));
        panelLabel.setHorizontalAlignment(SwingConstants.CENTER);

        longMessageLabel = new JLabel("Long Message:");
        longMessage = new JTextArea();
        longMessage.setLineWrap(true);
        longMessageScrollPane = new ScrollPane();
        longMessageScrollPane.add(longMessage);

        hashLabel = new JLabel("Hash:");
        hashTextArea = new JTextArea();
        hashTextArea.setLineWrap(true);
        hashScrollPane = new ScrollPane();
        hashScrollPane.add(hashTextArea);

        digitalSignatureLabel = new JLabel("Digital Signature:");
        digitalSignatureTextArea = new JTextArea();
        digitalSignatureTextArea.setLineWrap(true);
        digitalSignatureScrollPane = new ScrollPane();
        digitalSignatureScrollPane.add(digitalSignatureTextArea);

        verifiedButon = new JRadioButton("Verified");
        verifiedButon.setHorizontalAlignment(SwingConstants.CENTER);

        generateButton = new JButton("Generate");

    }

    public void AddContainer() {
        container.add(panelLabel);
        container.add(longMessageLabel);
        container.add(longMessageScrollPane);
        container.add(hashLabel);
        container.add(hashScrollPane);
        container.add(digitalSignatureLabel);
        container.add(digitalSignatureScrollPane);
        container.add(generateButton);
        container.add(verifiedButon);

    }

    public void SetBounds() {
        panelLabel.setBounds(0, 0, 400, 30);
        longMessageLabel.setBounds(10, 50, 400, 30);
        longMessageScrollPane.setBounds(10, 80, 400, 100);
        hashLabel.setBounds(10, 190, 380, 30);
        hashScrollPane.setBounds(10, 220, 380, 100);
        digitalSignatureLabel.setBounds(10, 330, 380, 30);
        digitalSignatureScrollPane.setBounds(10, 360, 380, 100);
        verifiedButon.setBounds(10, 470, 380, 30);
        generateButton.setBounds(10, 500, 380, 40);

    }

    public void AddActionListeners() {
        generateButton.addActionListener(e -> {
            try {
                Generate();
                // GenerateHashDigital();
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        });
        addWindowListener(new java.awt.event.WindowAdapter() {
            @Override
            public void windowClosed(java.awt.event.WindowEvent windowEvent) {
                new App();
            }
        });
    }

    public void Generate() throws Exception {
        // Uzun bir mesaj tanımlayın
        String message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Suspendisse justo arcu, dignissim nec dui cursus, iaculis aliquet tellus. Phasellus ut diam id odio molestie posuere sed fermentum sem. Integer iaculis pharetra interdum. Proin mauris mauris, sodales ut gravida non, aliquam quis ante. Praesent aliquet, sapien pharetra laoreet congue, tellus turpis fermentum lectus, vel sodales nisl massa ut nibh. Sed suscipit sem faucibus eros porta, sed lobortis odio vehicula. Pellentesque lorem dui, ultricies nec lacinia et, varius ac elit. Duis ullamcorper eros eget congue consectetur.";

        // RSA anahtar çifti oluşturma
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // SHA-256 kullanarak mesajın hash'ini oluşturma (mesaj özeti)
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(message.getBytes());

        // Özel anahtar kullanarak dijital imza oluşturma
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(hash);
        byte[] digitalSignature = signature.sign();

        // Sonuçları ekrana yazdırma
        System.out.println("Mesaj: " + message);
        longMessage.setText(message);
        hashTextArea.setText(bytesToHex(hash));
        digitalSignatureTextArea.setText(bytesToHex(digitalSignature));

        // Açık anahtar kullanarak dijital imzayı doğrulama
        signature.initVerify(publicKey);
        signature.update(hash);
        boolean isVerified = signature.verify(digitalSignature);
        verifiedButon.setSelected(isVerified);

    }

    // Byte dizisini hex string'e dönüştür
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02X", b));
        }
        return hex.toString();
    }

}
