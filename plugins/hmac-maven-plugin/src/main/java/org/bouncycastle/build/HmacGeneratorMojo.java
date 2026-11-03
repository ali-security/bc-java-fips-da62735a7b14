package org.bouncycastle.build;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Enumeration;
import java.util.Map;
import java.util.TreeMap;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

/* This file copies some code from other parts of BC-FIPS. This is done to avoid
   adding dependencies to other libraries, given that the code required is very small.
 */
@Mojo(name = "generate-hmac", defaultPhase = LifecyclePhase.PACKAGE)
public class HmacGeneratorMojo extends AbstractMojo {

    @Parameter(required = true)
    File jarFile;

    @Parameter(defaultValue = "Legion of the Bouncy Castle Inc.")
    String hmacKey;

    @Parameter(defaultValue = "HmacSHA256")
    String hmacAlgorithm;

    private static final String HMAC_FILE = "META-INF/HMAC.SHA256";

    @Override
    /* Own code */
    public void execute() throws MojoExecutionException {
        try {
            File tempFile = File.createTempFile(jarFile.getName(), null);
            tempFile.deleteOnExit();
            if(!jarFile.renameTo(tempFile)) {
                throw new MojoExecutionException("Cannot access existing jar " + jarFile.getName());
            }

            JarFile jar = new JarFile(tempFile);
            JarOutputStream jarOutputStream = new JarOutputStream(Files.newOutputStream(jarFile.toPath()));
            processJar(jar, jarOutputStream);
            jarOutputStream.close();
        } catch (IOException e) {
            throw new MojoExecutionException("Exception generating HMAC", e);
        }
    }

    /* Taken from bc-fips/src/main/java/org/bouncycastle/crypto/fips/FipsStatus.java */
    private static boolean skipEntry(JarEntry jarEntry)
    {
        if (jarEntry.isDirectory() || jarEntry.getName().indexOf("module-info.class") > 0)
        {
            return true;
        }

        if (jarEntry.getName().startsWith("META-INF/"))
        {
            if (jarEntry.getName().contains("OSGI-INF/"))
            {
                return true;
            }
            if (jarEntry.getName().indexOf("versions/") < 0)
            {
                return true;
            }
        }

        return false;
    }

    /*
        Slightly modified from bc-fips/src/main/java/org/bouncycastle/crypto/fips/FipsStatus.java
        Changes include:
        - Use JCE API instead of BC API
        - Build the new JAR, at the same time it is calculating the HMAC
        - Added writing the resulting HMAC to output JAR
    */
    private void processJar(JarFile jarFile, JarOutputStream jarOutputStream) throws MojoExecutionException
    {
        // this code is largely the standard approach to self verifying a JCE with some minor modifications. It will calculate
        // the SHA-256 HMAC on the classes.
        try
        {
            Mac mac = Mac.getInstance(hmacAlgorithm);
            mac.init(new SecretKeySpec(hmacKey.getBytes(), hmacAlgorithm));

            // build an index to make sure we get things in the same order.
            Map<String, JarEntry> index = new TreeMap<>();

            for (Enumeration<JarEntry> entries = jarFile.entries(); entries.hasMoreElements();)
            {
                JarEntry jarEntry = entries.nextElement();

                if(!HMAC_FILE.equals(jarEntry.getName())) {
                    getLog().debug("Processing entry " + jarEntry.getName());
                    writeJarEntry(jarOutputStream, jarEntry.getName(), jarFile.getInputStream(jarEntry));
                }

                // Skip directories, META-INF, and module-info.class meta-data
                if(skipEntry(jarEntry)) {
                    continue;
                }

                Object last = index.put(jarEntry.getName(), jarEntry);
                if (last != null)
                {
                   throw new IllegalStateException("Unable to calculate HMAC: duplicate entry found in jar file");
                }
            }

            byte[] buf = new byte[8192];
            for (Map.Entry<String, JarEntry> entry : index.entrySet())
            {
                JarEntry jarEntry = entry.getValue();
                InputStream is = jarFile.getInputStream(jarEntry);

                // Read in each jar entry. A SecurityException will
                // be thrown if a signature/digest check fails - if that happens
                // we'll just return an empty checksum

                // header information
                byte[] encName = jarEntry.getName().getBytes(StandardCharsets.UTF_8);
                mac.update((byte)0x5B);   // '['
                mac.update(encName, 0, encName.length);
                mac.update(longToBigEndian(jarEntry.getSize()), 0, 8);
                mac.update((byte)0x5D);    // ']'

                // contents
                int n;
                while ((n = is.read(buf, 0, buf.length)) != -1)
                {
                    mac.update(buf, 0, n);
                }
                is.close();
            }

            mac.update((byte)0x5B);   // '['
            byte[] encName = "END".getBytes(StandardCharsets.UTF_8);
            mac.update(encName, 0, encName.length);
            mac.update((byte)0x5D);    // ']'

            byte[] hmacResult = new byte[mac.getMacLength()];

            mac.doFinal(hmacResult, 0);

            byte[] readableMac = new byte[1 + (hmacResult.length*2)];
            encode(hmacResult, readableMac);
            readableMac[readableMac.length-1] = 0x0a; // LF

            writeJarEntry(jarOutputStream, HMAC_FILE, new ByteArrayInputStream(readableMac));
        }
        catch (Exception e)
        {
            throw new MojoExecutionException("Failed to compute HMAC", e);
        }
    }

    /* Own code */
    private void writeJarEntry(JarOutputStream jarOutputStream, String entryName, InputStream entryData) throws IOException {
        JarEntry jarEntry = new JarEntry(entryName);
        byte[] buf = new byte[1024];
        jarOutputStream.putNextEntry(jarEntry);
        int len;
        while ((len = entryData.read(buf)) > 0) {
            jarOutputStream.write(buf, 0, len);
        }
        jarOutputStream.closeEntry();
    }


    /* Adapted from bc-fips/src/main/java/org/bouncycastle/util/encoders/HexEncoder.java */
    private final byte[] encodingTable =
    {
            (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6', (byte)'7',
            (byte)'8', (byte)'9', (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f'
    };

    /* Adapted from bc-fips/src/main/java/org/bouncycastle/util/encoders/HexEncoder.java */
    private void encode(byte[] inBuf, byte[] outBuf) {
        int inPos = 0;
        int inEnd = inBuf.length;
        int outPos = 0;

        while (inPos < inEnd)
        {
            int b = inBuf[inPos++] & 0xFF;

            outBuf[outPos++] = encodingTable[b >>> 4];
            outBuf[outPos++] = encodingTable[b & 0xF];
        }
    }

    /* Taken from bc-fips/src/main/java/org/bouncycastle/util/Pack.java */
    private byte[] longToBigEndian(long n)
    {
        byte[] bs = new byte[8];
        intToBigEndian((int)(n >>> 32), bs, 0);
        intToBigEndian((int)(n & 0xffffffffL), bs, 4);
        return bs;
    }

    /* Taken from bc-fips/src/main/java/org/bouncycastle/util/Pack.java */
    private void intToBigEndian(int n, byte[] bs, int off)
    {
        bs[off] = (byte)(n >>> 24);
        bs[++off] = (byte)(n >>> 16);
        bs[++off] = (byte)(n >>> 8);
        bs[++off] = (byte)(n);
    }

}
