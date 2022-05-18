package com.trantor.app.controller;

import com.trantor.app.encryptor.PgpEncryptor;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/file")
public class AppController {

    private final PgpEncryptor encryptor;

    // client public key
//    private static final String PUBLIC_KEY_FILE = "C:\\Users\\paramjeet.malik\\Desktop\\EncryptorB\\NASA FCU.asc";

    // csv file
    private static final String INPUT_FILE_NAME = "D:\\Test\\EncryptorB\\textFileToEncrypt.csv";


    // public key for testing
    private static final String PUBLIC_KEY_FILE = "D:\\Test\\EncryptorB\\IITCorporation_1024.asc";

    // txt file
//    private static final String INPUT_FILE_NAME = "D:\\Test\\EncryptorB\\textToEncrypt.txt";

    // encrypted file
    private static final String OUTPUT_FILE_NAME = "D:\\Test\\EncryptorB\\EncryptedFile.bpg";

    @GetMapping("/encrypt")
    public ResponseEntity<String> getFile() throws Exception {


        encryptor.encryption(PUBLIC_KEY_FILE, INPUT_FILE_NAME, OUTPUT_FILE_NAME);

        System.out.println("File Encrypted successfully");


        return new ResponseEntity<>("Done", HttpStatus.ACCEPTED);
    }

}
