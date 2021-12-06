package com.homeofcode.https;

import com.homeofcode.oauth.AppServer;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.regex.Pattern;

import static java.net.HttpURLConnection.HTTP_INTERNAL_ERROR;

public class SimpleHttpsServer {
    /** this is for the in-memory KeyStore we don't need a password really */
    public static final char[] noPass = "noPass".toCharArray();

    public static final Path keyPath = Path.of("key.pem");
    public static final Path serverCertPath = Path.of("server.pem");

    private static final String pemKeyConst = "BEGIN PRIVATE KEY";
    private static final String pemCertConst = "BEGIN CERTIFICATE";

    // code snippet from https://stackoverflow.com/questions/42675033/how-to-build-a-sslsocketfactory-from-pem-certificate-and-key-without-converting
    KeyStore getKeyStore() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        byte[] keyBytes = getPemBytes(SimpleHttpsServer.keyPath, SimpleHttpsServer.pemKeyConst);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        var alg = spec.getAlgorithm();
        if (alg == null) alg = "RSA";
        KeyFactory kf = KeyFactory.getInstance(alg);
        Key serverKey = kf.generatePrivate(spec);
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        byte[] certBytes = getPemBytes(SimpleHttpsServer.serverCertPath, SimpleHttpsServer.pemCertConst);
        Certificate serverCertificate = cf.generateCertificate(new ByteArrayInputStream(certBytes));
        ks.setKeyEntry("serverKey", serverKey, SimpleHttpsServer.noPass, new Certificate[]{serverCertificate});
        ks.setCertificateEntry("serverCert", serverCertificate);
        return ks;
    }

    private static final Pattern pemRE = Pattern.compile("---*([^-\n]+)-+\n([^-]+)\n---*([^-]+)-+\n");

    private static byte[] getPemBytes(Path path, String pemConst) throws IOException {
        String str = Files.readString(path);
        var match = SimpleHttpsServer.pemRE.matcher(str);
        if (!match.matches()) {
            throw new IOException(String.format("%s is not a PEM file", path.toString()));
        }
        String pemType = match.group(1);
        if (!pemType.equals(pemConst)) {
            throw new IOException(String.format("key file should start with %s but starts with %s",
                    pemConst, pemType));
        }
        return Base64.getDecoder().decode(match.group(2).replaceAll("\n", ""));
    }

    private HttpsServer httpsServer;

    public SimpleHttpsServer() throws IOException, NoSuchAlgorithmException {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        try {
            KeyStore ks = getKeyStore();
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, noPass);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println(e.getMessage());
            System.exit(2);
        }

        httpsServer = HttpsServer.create();
        httpsServer.bind(new InetSocketAddress(443), 10);
        httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext));
    }

    public String[] addToHttpsServer(final AppServer appServer) throws NoSuchAlgorithmException, IOException {
        var methodsAdded = new ArrayList<String>();
        for (final Method m : appServer.getClass().getDeclaredMethods()) {
            if (m.isAnnotationPresent(HttpPath.class)) {
                if ((m.getModifiers() & Modifier.PUBLIC) != Modifier.PUBLIC) {
                    System.out.printf("skipping %s because not public\n", m.getName());
                    continue;
                }
                methodsAdded.add(m.getName());
                String path = m.getAnnotation(HttpPath.class).path();
                httpsServer.createContext(path, createHandler(appServer, m));
            }
        }
        return methodsAdded.toArray(new String[0]);
    }

    private HttpHandler createHandler(final AppServer appServer, final Method m) {
        return new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) {
                try {
                    m.invoke(appServer, exchange);
                } catch (Exception e) {
                    if (e instanceof InvocationTargetException) {
                        e = (Exception)e.getCause();
                    }
                    e.printStackTrace();
                    try {
                        exchange.sendResponseHeaders(HTTP_INTERNAL_ERROR, -1);
                        OutputStream os = exchange.getResponseBody();
                        os.write(
                                String.format("Error processing request: %s\n", e.getMessage()).getBytes()
                        );
                        os.close();
                        exchange.getRequestBody().close();
                    } catch (Exception ee) {
                    }
                }
            }
        };
    }

    public void start() {
        httpsServer.start();
    }
}
