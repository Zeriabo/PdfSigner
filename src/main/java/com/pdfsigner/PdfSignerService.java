package com.pdfsigner;

import jakarta.enterprise.context.ApplicationScoped;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Base64;

@ApplicationScoped
public class PdfSignerService {

    public File signPdf(File inputFile, String name, String reason, String location) throws Exception {

        String keystorePassword = "12341234";
        String alias = "pdfsigner";

        File signedFile = new File("/tmp/signed_output.pdf");

        KeyStore keystore = KeyStore.getInstance("PKCS12");

        try (InputStream fis = getClass().getClassLoader().getResourceAsStream("signer.p12")) {
            if (fis == null) {
                throw new FileNotFoundException("signer.p12 not found in resources.");
            }
            keystore.load(fis, keystorePassword.toCharArray());
        }

        PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, keystorePassword.toCharArray());
        Certificate[] certChain = keystore.getCertificateChain(alias);

        if (privateKey == null) {
            throw new IllegalArgumentException("Private key not found in the keystore");
        }
        if (certChain == null || certChain.length == 0) {
            throw new IllegalArgumentException("Certificate chain is empty");
        }

        try (PDDocument document = PDDocument.load(inputFile);
                FileOutputStream outputStream = new FileOutputStream(signedFile)) {

            PDSignature signature = new PDSignature();
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
            signature.setName(name);
            signature.setReason(reason);
            signature.setLocation(location);

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

            document.saveIncremental(outputStream);
        }

        return signedFile;
    }

    private String getDocumentHash(File documentFile) throws Exception {
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
}
