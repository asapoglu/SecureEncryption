package computersystemsecurity;

import java.awt.Container;
import java.awt.Font;
import java.awt.Image;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.swing.BorderFactory;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.SwingConstants;

public class AESFileEncryption extends JFrame {

    Container container;
    JFileChooser fileChooser;
    JButton encryptButton, decryptButton, openImageButton;
    JLabel imageLabel,panelLabel;
    String outputPath, inputFilePath;
    SecretKey key128;
    SecretKey key256;
    byte[] iv;
    byte[] newIV;


    public AESFileEncryption() {
        super("AES File Encryption");
        Initialize();

    }
    public void Initialize() {
        CreateComponents();
        AddContainer();
        SetBounds();
        AddActionListeners();

        this.setSize(400, 550);
        this.setLocationRelativeTo(null);
        this.setVisible(true);

        this.setResizable(true);
        this.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
    }

    public void CreateComponents() {
        container = getContentPane();
        container.setLayout(null);
        panelLabel = new JLabel("AES File Encryption");
        panelLabel.setFont(new Font("Courier", Font.BOLD, 20));
        panelLabel.setHorizontalAlignment(SwingConstants.CENTER);
        encryptButton = new JButton("Encrypt");
        decryptButton = new JButton("Decrypt");
        openImageButton = new JButton("Open Image");
        imageLabel = new JLabel();
        imageLabel.setHorizontalAlignment(JLabel.CENTER); // Resmi ortala
        imageLabel.setVerticalAlignment(JLabel.CENTER);
        imageLabel.setBorder(BorderFactory.createRaisedBevelBorder());

    }

    public void AddContainer() {
        container.add(encryptButton);
        container.add(decryptButton);
        container.add(openImageButton);
        container.add(imageLabel);
        container.add(panelLabel);
    }

    public void SetBounds() {
        panelLabel.setBounds(50, 10, 300, 30);
        encryptButton.setBounds(20, 50, 170, 40);
        decryptButton.setBounds(210, 50, 170, 40);
        openImageButton.setBounds(20, 100, 360, 40);
        imageLabel.setBounds(20, 150, 360, 360);
    }

    public void AddActionListeners() {

        openImageButton.addActionListener(e -> OpenImage());
        encryptButton.addActionListener(e -> {
            try {
                if (inputFilePath == null) {
                    JOptionPane.showMessageDialog(this, "Please select an image first!");
                    return;
                }
                key128 = GenerateAESKey(128);
                key256 = GenerateAESKey(256);
                iv = GenerateIV();
                newIV = GenerateIV();

                long cbc128 = ProcessEncryption(inputFilePath, outputPath + "/Image_128CBC.txt", key128, iv,
                        "AES/CBC/PKCS5Padding");
                long cbc256 = ProcessEncryption(inputFilePath, outputPath + "/Image_256CBC.txt", key256, iv,
                        "AES/CBC/PKCS5Padding");
                long ctr256 = ProcessEncryption(inputFilePath, outputPath + "/Image_256CTR.txt", key256, iv,
                        "AES/CTR/NoPadding");
                long cbc128NewIv = ProcessEncryption(inputFilePath, outputPath + "/Image_NewIV_128CBC.txt", key128,
                        newIV, "AES/CBC/PKCS5Padding");

                JOptionPane.showMessageDialog(this,
                        "Encryption completed successfully!\nCBC 128: " + cbc128 + " ms\n" + "CBC 128 New IV: "
                                + cbc128NewIv + " ms\n" + "CBC 256: " + cbc256 + " ms\n" + "CTR 256: " + ctr256
                                + " ms\n");
            } catch (Exception exception) {
                exception.printStackTrace();
            }
        });
        decryptButton.addActionListener(e -> {
            try {
                if (outputPath == null) {
                    JOptionPane.showMessageDialog(this, "Please select an image first!");
                    return;
                }

               long cbc128 = ProcessDecryption(outputPath + "/Image_128CBC.txt", key128, iv, "AES/CBC/PKCS5Padding");
               long cbc256 = ProcessDecryption(outputPath + "/Image_256CBC.txt", key256, iv, "AES/CBC/PKCS5Padding");
               long ctr256 = ProcessDecryption(outputPath + "/Image_256CTR.txt", key256, iv, "AES/CTR/NoPadding");
               long cbc128NewIV = ProcessDecryption(outputPath + "/Image_NewIV_128CBC.txt", key128, newIV, "AES/CBC/PKCS5Padding");

                JOptionPane.showMessageDialog(this,
                        "Decryption completed successfully!\nCBC 128: " + cbc128 + " ms\n" + "CBC 128 New IV: "
                                + cbc128NewIV + " ms\n" + "CBC 256: " + cbc256 + " ms\n" + "CTR 256: " + ctr256
                                + " ms\n");

            } catch (Exception exception) {
                exception.printStackTrace();
            }
        });

        addWindowListener(new java.awt.event.WindowAdapter() {
            @Override
            public void windowClosed(java.awt.event.WindowEvent windowEvent) {
                new App();
            }
        });

    }

    private void OpenImage() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setCurrentDirectory(new File(System.getProperty("user.home")));
        fileChooser.setDialogTitle("Resim Seçin");
        fileChooser.setAcceptAllFileFilterUsed(false);
        fileChooser.addChoosableFileFilter(
                new javax.swing.filechooser.FileNameExtensionFilter("Image files", "jpg", "png", "gif", "bmp"));

        // Dosya seçiciyi açma ve sonuç kontrolü
        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            inputFilePath = selectedFile.getAbsolutePath();
            outputPath = selectedFile.getParent();
            ImageIcon imageIcon = new ImageIcon(inputFilePath);
            AdjustLabelSize(imageIcon);
        }
    }

    private void AdjustLabelSize(ImageIcon imageIcon) {
        Image image = imageIcon.getImage();
        // ImageIcon boyutunu JLabel boyutuna uyacak şekilde ayarlama
        int labelWidth = imageLabel.getWidth();
        int labelHeight = imageLabel.getHeight();
        double aspectRatio = (double) imageIcon.getIconWidth() / imageIcon.getIconHeight();

        // Resim orijinal en-boy oranını koruyacak şekilde boyutlandırılır
        if (labelWidth / aspectRatio <= labelHeight) {
            labelHeight = (int) (labelWidth / aspectRatio);
        } else {
            labelWidth = (int) (labelHeight * aspectRatio);
        }
        image = image.getScaledInstance(labelWidth, labelHeight, Image.SCALE_SMOOTH);
        imageLabel.setIcon(new ImageIcon(image));
        imageLabel.setText(""); // Eğer resim yüklenemezse gösterilen metni temizle
        imageLabel.setBounds((this.getWidth() - labelWidth) / 2, 150, labelWidth, labelHeight);
    }

    private SecretKey GenerateAESKey(int keySize) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(keySize);
        return keyGenerator.generateKey();
    }

    private byte[] GenerateIV() {
        byte[] iv = new byte[16]; // AES için genellikle 16 byte (128 bit) IV kullanılır
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    private long ProcessEncryption(String inputPath, String outputBase64Path, SecretKey key, byte[] iv,
            String cipherInstance) throws Exception {
        // Şifreleme işlemi
        String encryptedFilePath = outputBase64Path;
        long encryptionTime = EncryptFile(inputPath, encryptedFilePath, key, iv, cipherInstance);
        System.out.println(outputBase64Path + " Encryption time: " + encryptionTime + " ms");

        // Şifrelenmiş veriyi Base64 ile kodla dosyaya yaz
        byte[] encryptedData = Files.readAllBytes(Paths.get(encryptedFilePath));
        String encodedData = Base64.getEncoder().encodeToString(encryptedData);
        Files.write(Paths.get(outputBase64Path), encodedData.getBytes());
        return encryptionTime;
    }

    private long ProcessDecryption(String outputBase64Path, SecretKey key, byte[] iv, String cipherInstance)
            throws Exception {
        // Şifrelenmiş ve kodlanmış veriyi dosyadan oku dekodla ve şifresini çöz
        byte[] encodedDataV = Files.readAllBytes(Paths.get(outputBase64Path));
        byte[] decodedData = Base64.getDecoder().decode(encodedDataV);
        String decryptedFilePath = outputBase64Path.replace(".txt", "_decrypted.jpg");
        long decryptionTime = DecryptFile(decodedData, decryptedFilePath, key, iv, cipherInstance);
        System.out.println("Decryption time: " + decryptionTime + " ms");
        return decryptionTime;
    }

    private long EncryptFile(String inputPath, String outputPath, SecretKey key, byte[] iv, String cipherInstance)
            throws Exception {
        Cipher cipher = Cipher.getInstance(cipherInstance);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        return ProcessFile(inputPath, outputPath, cipher);
    }

    private long DecryptFile(byte[] inputData, String outputPath, SecretKey key, byte[] iv, String cipherInstance)
            throws Exception {
        long startTime = System.currentTimeMillis();
        Cipher cipher = Cipher.getInstance(cipherInstance);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        try (FileOutputStream fos = new FileOutputStream(outputPath)) {
            byte[] output = cipher.doFinal(inputData);
            fos.write(output);
        }
        long endTime = System.currentTimeMillis();
        return endTime - startTime;
    }

    private long ProcessFile(String inputPath, String outputPath, Cipher cipher) throws Exception {
        long startTime = System.currentTimeMillis();
        try (FileInputStream fis = new FileInputStream(inputPath);
                FileOutputStream fos = new FileOutputStream(outputPath)) {
            byte[] bytes = new byte[4096];
            int numBytes;
            while ((numBytes = fis.read(bytes)) != -1) {
                byte[] output = cipher.update(bytes, 0, numBytes);
                if (output != null) {
                    fos.write(output);
                }
            }
            byte[] finalBytes = cipher.doFinal();
            if (finalBytes != null) {
                fos.write(finalBytes);
            }
        }
        long endTime = System.currentTimeMillis();
        return endTime - startTime;
    }
}
