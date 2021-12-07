package com.homeofcode.oauth;

import com.homeofcode.https.HttpPath;
import com.homeofcode.https.SimpleHttpsServer;
import com.sun.net.httpserver.HttpExchange;
import org.json.JSONObject;

import javax.net.ssl.HttpsURLConnection;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
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

import static java.lang.System.Logger.Level.INFO;
import static java.net.HttpURLConnection.HTTP_BAD_REQUEST;
import static java.net.HttpURLConnection.HTTP_MOVED_TEMP;
import static java.net.HttpURLConnection.HTTP_OK;

public class AppServer {
    final static String OPEN_ID_ENDPT = "https://accounts.google.com/.well-known/openid-configuration";
    static System.Logger LOG = System.getLogger(AppServer.class.getPackageName());
    static String errorHTML;
    static String successHTML;

    static {
        try {
            errorHTML = getResource("/pages/error.html");
            successHTML = getResource("/pages/success.html");
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    String authURL;
    Random rand = new Random();
    String clientId;
    String clientSecret;
    String redirectURL;
    String tokenEndpoint;
    String authEndpoint;
    HashMap<String, NonceRecord> nonces = new HashMap<>();

    AppServer(String clientId, String clientSecret) throws IOException {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        var nonceRecord =
                new NonceRecord(Long.toHexString(rand.nextLong()), Long.toHexString(rand.nextLong()), new Date());

        redirectURL = "https://cloud.homeofcode.com/login/callback";

        var endptsStr = new String(new URL(OPEN_ID_ENDPT).openConnection().getInputStream().readAllBytes());
        var endpts = new JSONObject(endptsStr);
        tokenEndpoint = endpts.getString("token_endpoint");
        authEndpoint = endpts.getString("authorization_endpoint");

        authURL = String.format(
                "%s?" + "response_type=code&scope=openid%%20email" + "&client_id=%s" + "&redirect_uri=%s" +
                        "&state=%s" + "&nonce=%s" + "&hd=sjsu.edu", authEndpoint, clientId, redirectURL,
                nonceRecord.state, nonceRecord.nonce);
    }

    static private String getResource(String path) throws IOException {
        var stream = AppServer.class.getResourceAsStream(path);
        if (stream == null) throw new FileNotFoundException(path);
        return new String(stream.readAllBytes());
    }

    private static void redirect(HttpExchange exchange, String redirectURL) throws IOException {
        exchange.getRequestBody().close();
        exchange.getResponseHeaders().add("Location", redirectURL);
        exchange.sendResponseHeaders(HTTP_MOVED_TEMP, 0);
        exchange.getResponseBody().write(String.format("<a href=%1$s>%1$s</a>", redirectURL).getBytes());
        exchange.getResponseBody().close();
    }

    private static HashMap<String, String> extractParams(HttpExchange exchange) {
        var params = new HashMap<String, String>();
        for (var param : exchange.getRequestURI().getQuery().split("&")) {
            var keyVal = param.split("=", 2);
            params.put(keyVal[0], URLDecoder.decode(keyVal[1], Charset.defaultCharset()));
        }
        return params;
    }

    private static void sendOKResponse(HttpExchange exchange, byte[] response) throws IOException {
        exchange.getRequestBody().close();
        exchange.sendResponseHeaders(HTTP_OK, response.length);
        try (var os = exchange.getResponseBody()) {
            os.write(response);
        }
    }

    public static void main(String[] args) {
        try {
            System.setProperty("java.util.logging.SimpleFormatter.format", "%1$tF %1$tT %4$s %5$s%n");
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
                LOG.log(INFO, "added {0}", add);
            }
            simpleHttpsServer.start();

        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    @HttpPath(path = "/login")
    public void loginPage(HttpExchange exchange) throws Exception {
        redirect(exchange, authURL);
    }

    @HttpPath(path = "/login/callback")
    public void loginCallback(HttpExchange exchange) throws Exception {
        HashMap<String, String> params = extractParams(exchange);
        exchange.getRequestBody().close();
        if (params.containsKey("error")) {
            redirect(exchange, String.format("/login/error?error=%s",
                    URLEncoder.encode(params.get("error"), Charset.defaultCharset())));
            return;
        }
        var code = params.get("code");
        LOG.log(INFO, "starting post");
        var con = (HttpsURLConnection) new URL(tokenEndpoint).openConnection();
        con.setDoOutput(true);
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        String request =
                String.format("code=%s&client_id=%s&client_secret=%s&redirect_uri=%s&grant_type=authorization_code",
                        URLEncoder.encode(code, Charset.defaultCharset()),
                        URLEncoder.encode(clientId, Charset.defaultCharset()),
                        URLEncoder.encode(clientSecret, Charset.defaultCharset()),
                        URLEncoder.encode(redirectURL, Charset.defaultCharset()));
        try (OutputStream os = con.getOutputStream()) {
            os.write(request.getBytes());
        }
        var baos = new ByteArrayOutputStream();
        try (InputStream is = con.getResponseCode() < HTTP_BAD_REQUEST ? con.getInputStream() : con.getErrorStream()) {
            is.transferTo(baos);
        }
        LOG.log(INFO, "finished post");
        String response = baos.toString();
        var json = new JSONObject(response);
        if (json.has("error")) {
            redirect(exchange, String.format("/login/error?error=%s",
                    URLEncoder.encode(json.getString("error"), Charset.defaultCharset())));
            return;
        }

        // extract the email from the JWT token
        String idToken = json.getString("id_token");
        var tokenParts = idToken.split("\\.");
        var info = new JSONObject(new String(Base64.getUrlDecoder().decode(tokenParts[1])));
        var email = info.getString("email");
        redirect(exchange,
                String.format("/login/success?email=%s", URLEncoder.encode(email, Charset.defaultCharset())));
    }

    @HttpPath(path = "/login/error")
    public void loginError(HttpExchange exchange) throws Exception {
        var error = extractParams(exchange).get("error");
        byte[] response = errorHTML.replace("ERROR", error).getBytes();
        sendOKResponse(exchange, response);
    }

    @HttpPath(path = "/login/success")
    public void loginSuccess(HttpExchange exchange) throws Exception {
        var email = extractParams(exchange).get("email");
        byte[] response = successHTML.replace("EMAIL", email).getBytes();
        sendOKResponse(exchange, response);
    }

    record NonceRecord(String nonce, String state, Date createTime) {
    }
}
