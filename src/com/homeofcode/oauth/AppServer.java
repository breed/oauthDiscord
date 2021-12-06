package com.homeofcode.oauth;


import com.homeofcode.https.HttpPath;
import com.homeofcode.https.SimpleHttpsServer;
import com.sun.net.httpserver.HttpExchange;
import org.json.JSONObject;

import javax.net.ssl.HttpsURLConnection;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Properties;
import java.util.Random;

import static java.net.HttpURLConnection.HTTP_BAD_REQUEST;
import static java.net.HttpURLConnection.HTTP_MOVED_TEMP;
import static java.net.HttpURLConnection.HTTP_OK;

public class AppServer {

    final static String OPEN_ID_ENDPT = "https://accounts.google.com/.well-known/openid-configuration";

    String authURL;
    Random rand = new Random();
    String clientId;
    String clientSecret;
    String redirectURL;
    String tokenEndpoint;
    String authEndpoint;

    record NonceRecord(String nonce, String state, Date createTime) {
    }

    HashMap<String, NonceRecord> nonces = new HashMap<>();

    AppServer(String clientId, String clientSecret) throws IOException {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        var nonceRecord = new NonceRecord(
                Long.toHexString(rand.nextLong()),
                Long.toHexString(rand.nextLong()),
                new Date());

        redirectURL = String.format("https://cloud.homeofcode.com/login/callback");

        var endptsStr = new String(new URL(OPEN_ID_ENDPT).openConnection().getInputStream().readAllBytes());
        var endpts = new JSONObject(endptsStr);
        tokenEndpoint = endpts.getString("token_endpoint");
        authEndpoint = endpts.getString("authorization_endpoint");

        authURL = String.format(
                "%s?" +
                        "response_type=code&scope=openid%%20email" +
                        "&client_id=%s" +
                        "&redirect_uri=%s" +
                        "&state=%s" +
                        "&nonce=%s" +
                        "&hd=sjsu.edu",
                authEndpoint,
                clientId,
                redirectURL,
                nonceRecord.state,
                nonceRecord.nonce
        );
        System.out.println(endpts);
    }

    @HttpPath(path = "/login")
    public void loginPage(HttpExchange exchange) throws Exception {
        exchange.getRequestBody().close();
        exchange.getResponseHeaders().add("Location", authURL);
        exchange.sendResponseHeaders(HTTP_MOVED_TEMP, 0);
        exchange.getResponseBody().write(String.format("<a href=%s>%s</a>", authURL, authURL).getBytes());
        exchange.getResponseBody().close();
        if (true) return;
        File loginPageFile = new File("loginPage.html");
        try (FileInputStream fis = new FileInputStream(loginPageFile)) {
            exchange.getRequestBody().close();
            exchange.sendResponseHeaders(HTTP_OK, loginPageFile.length());
            try (OutputStream os = exchange.getResponseBody()) {
                fis.transferTo(os);
            }
        }
    }

    @HttpPath(path = "/login/callback")
    public void loginCallback(HttpExchange exchange) throws Exception {
        System.out.println("In loginCallback");
        var params = new HashMap<String, String>();
        for (var param : exchange.getRequestURI().getQuery().split("&")) {
            var keyVal = param.split("=", 2);
            params.put(keyVal[0], URLDecoder.decode(keyVal[1], Charset.defaultCharset()));
        }
        exchange.getRequestBody().close();
        System.out.println("Got " + params);
        if (params.containsKey("error")) {
            exchange.sendResponseHeaders(HTTP_OK, 0);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(String.format("<html><h1>error: %s</h1></html>", params.get("error")).getBytes());
                return;
            }
        }
        var code = params.get("code");
        var scope = params.get("scope");
        var emailURL = scope.split(" ")[2];
        System.out.println("Posting to " + emailURL);
        var con = (HttpsURLConnection) new URL(tokenEndpoint).openConnection();
        con.setDoOutput(true);
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        System.out.println("writing post body");
        String request = String.format("code=%s&client_id=%s&client_secret=%s&redirect_uri=%s&grant_type=authorization_code",
                URLEncoder.encode(code, Charset.defaultCharset()),
                URLEncoder.encode(clientId, Charset.defaultCharset()),
                URLEncoder.encode(clientSecret, Charset.defaultCharset()),
                URLEncoder.encode(redirectURL, Charset.defaultCharset()));
        try (OutputStream os = con.getOutputStream()) {
            System.out.println(request);
            os.write(request.getBytes());
        }
        System.out.println("Doing input " + con.getResponseCode());
        var baos = new ByteArrayOutputStream();
        try (InputStream is =
                     con.getResponseCode() < HTTP_BAD_REQUEST ? con.getInputStream() : con.getErrorStream()) {
            is.transferTo(baos);
        }
        String response = new String(baos.toByteArray());
        System.out.println(response);
        var json = new JSONObject(response);
        String idToken = json.getString("id_token");
        System.out.println(idToken);
        var tokenParts = idToken.split("\\.");
        System.out.println(tokenParts[1]);
        var info = new JSONObject(new String(Base64.getUrlDecoder().decode(tokenParts[1])));
        System.out.println(info);
        System.out.println("done");
    }

    public static void main(String[] args) {
        try {
            if (args.length != 1) {
                System.out.println("USAGE: appserver properties_config_file");
                System.exit(2);
            }
            Properties properties = new Properties();
            properties.load(new FileReader(args[0]));
            var clientId = properties.getProperty("clientId");
            if (clientId == null) {
                System.out.println("clientId property missing from " + args[0]);
                System.exit(1);
            }
            var clientSecret = properties.getProperty("clientSecret");
            if (clientSecret == null) {
                System.out.println("clientSecret property missing from " + args[0]);
                System.exit(1);
            }
            var appServer = new AppServer(clientId, clientSecret);

            var simpleHttpsServer = new SimpleHttpsServer();
            var added = simpleHttpsServer.addToHttpsServer(appServer);
            for (var add : added) {
                System.out.printf("added %s\n", add);
            }
            simpleHttpsServer.start();

        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

}
