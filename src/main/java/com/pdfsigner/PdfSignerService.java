package com.pdfsigner;

import jakarta.enterprise.context.ApplicationScoped;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.net.HttpURLConnection;
import java.net.URL;
import java.io.OutputStream;
import org.json.JSONObject;

@ApplicationScoped
public class PdfSignerService {

    // OAuth token from Bank API (for authenticating requests)
    private static final String OAUTH_TOKEN = "YOUR_OAUTH_TOKEN";

    public File signPdf(File inputFile) throws Exception {
        // Load PKCS#12 certificate from resources
        String keystorePassword = "12341234";
        String alias = "pdfsigner";

        File signedFile = new File("/tmp/signed_output.pdf");

        // Load the PKCS#12 keystore using ClassLoader
        KeyStore keystore = KeyStore.getInstance("PKCS12");

        try (InputStream fis = getClass().getClassLoader().getResourceAsStream("signer.p12")) {
            if (fis == null) {
                throw new FileNotFoundException("signer.p12 not found in resources.");
            }
            keystore.load(fis, keystorePassword.toCharArray());
        }

        PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, keystorePassword.toCharArray());
        Certificate[] certChain = keystore.getCertificateChain(alias);

        // Ensure the private key and certificates are not null
        if (privateKey == null) {
            throw new IllegalArgumentException("Private key not found in the keystore");
        }
        if (certChain == null || certChain.length == 0) {
            throw new IllegalArgumentException("Certificate chain is empty");
        }

        // Sign the PDF
        try (PDDocument document = PDDocument.load(inputFile);
             FileOutputStream outputStream = new FileOutputStream(signedFile)) {

            PDSignature signature = new PDSignature();
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
            signature.setName("Quarkus Signer");
            signature.setReason("PDF Digital Signature");
            signature.setLocation("Quarkus App");

            // Add the signature to the document
            document.addSignature(signature, content -> {
                try {
                    Signature sig = Signature.getInstance("SHA256withRSA");
                    sig.initSign(privateKey);

                    byte[] buffer = new byte[8192];
                    int bytesRead;
                    while ((bytesRead = content.read(buffer)) != -1) {
                        sig.update(buffer, 0, bytesRead);
                    }

                    return sig.sign();
                } catch (Exception e) {
                    throw new IOException("Error during signature process", e);
                }
            });

            // Now we request the bank API for signature verification
            String documentHash = getDocumentHash(inputFile);
            boolean isValidSigner = verifySignerWithBank(documentHash);

            if (isValidSigner) {
                // Save the signed document if the bank verifies the signer
                document.saveIncremental(outputStream);
            } else {
                throw new Exception("Signer identity verification failed by bank.");
            }
        }

        return signedFile;
    }

    private String getDocumentHash(File documentFile) throws Exception {
        // Generate a hash (SHA256) of the document to send to the bank for verification
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (FileInputStream fis = new FileInputStream(documentFile)) {
            byte[] byteArray = new byte[8192];
            int bytesRead;
            while ((bytesRead = fis.read(byteArray)) != -1) {
                digest.update(byteArray, 0, bytesRead);
            }
        }
        return Base64.getEncoder().encodeToString(digest.digest());
    }

    private boolean verifySignerWithBank(String documentHash) throws Exception {
        // Send the document hash to the bank API to verify the signer's identity
        URL url = new URL("https://api.op.fi/v1/signature-verification");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Authorization", "Bearer " + OAUTH_TOKEN);
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setDoOutput(true);

        // Create the JSON request body
        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("documentHash", documentHash);

        // Send the request
        try (OutputStream os = connection.getOutputStream()) {
            byte[] input = new JSONObject(requestBody).toString().getBytes("utf-8");
            os.write(input, 0, input.length);
        }

        // Read the response
        int responseCode = connection.getResponseCode();
        if (responseCode == 200) {
            // Assuming the response includes a field "isValid" indicating whether the signature is valid
            String responseBody = new String(connection.getInputStream().readAllBytes(), "utf-8");
            JSONObject jsonResponse = new JSONObject(responseBody);
            return jsonResponse.getBoolean("isValid");
        } else {
            throw new Exception("Bank signature verification failed: " + responseCode);
        }
    }
}
