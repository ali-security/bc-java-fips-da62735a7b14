package org.bouncycastle.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Enumeration;
import java.util.Map;
import java.util.TreeMap;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.NativeServices;
import org.bouncycastle.crypto.OutputMACCalculator;
import org.bouncycastle.crypto.SymmetricKey;
import org.bouncycastle.crypto.SymmetricSecretKey;
import org.bouncycastle.crypto.UpdateOutputStream;
import org.bouncycastle.crypto.fips.FipsAES;
import org.bouncycastle.crypto.fips.FipsDH;
import org.bouncycastle.crypto.fips.FipsDRBG;
import org.bouncycastle.crypto.fips.FipsDSA;
import org.bouncycastle.crypto.fips.FipsEC;
import org.bouncycastle.crypto.fips.FipsEdEC;
import org.bouncycastle.crypto.fips.FipsKDF;
import org.bouncycastle.crypto.fips.FipsPBKD;
import org.bouncycastle.crypto.fips.FipsRSA;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.fips.FipsStatus;
import org.bouncycastle.crypto.fips.FipsTripleDES;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.util.encoders.Hex;

/**
 * Executable class that displays information about the module
 */
public class DumpInfo
{
    private static final String[] classes = new String[]{FipsAES.class.getName(), FipsTripleDES.class.getName(), FipsDH.class.getName(),
            FipsSHS.class.getName(), FipsDRBG.class.getName(), FipsDSA.class.getName(), FipsEdEC.class.getName(), FipsEC.class.getName(),
            FipsKDF.class.getName(), FipsPBKD.class.getName(), FipsRSA.class.getName()};
    
    public static void main(String[] args)
    {
        if (args.length > 0)
        {
            if (args[0].equals("-verbose"))
            {
                // -DM out.println
                System.out.print(buildInfoString(true));
            }
            else if (args[0].equals("-c"))
            {
                // -DM out.println
                System.out.println(Strings.fromByteArray(Hex.encode(FipsStatus.getModuleHMAC())));
                // -DM err.println
                System.err.println("Generated new HMAC");
            }
            else if (args[0].equals("-a") && args.length > 1)
            {
                try
                {
                    JarFile jf = new JarFile(args[1]);
                    // -DM out.println
                    System.out.println(Strings.fromByteArray(Hex.encode(calculateModuleHMAC(jf))));
                    // -DM err.println
                    System.err.println("Generated new HMAC for Jar file " + args[1]);
                }
                catch (IOException e)
                {
                    // -DM err.println
                    System.err.println("Unable to open Jar file " + args[1]);
                }
            }
            else
            {
                // -DM err.println
                System.err.println("Invalid command line arguments.");
            }
        }
        else
        {
            // -DM out.println
            System.out.print(buildInfoString(false));
        }
    }

    /**
     * Return a string representing an information dump on the module as created.
     *
     * @param verbose if true, include possible native support regardless of whether native is enabled, including libraries loaded if appropriate.
     * @return a string representing an information dump on the module instantiation.
     */
    public static String getInfoString(boolean verbose)
    {
        return buildInfoString(verbose);
    }

    private static String buildInfoString(boolean all)
    {
        StringBuilder sBld = new StringBuilder();
        String newLine = System.lineSeparator();

        runTests();

        sBld.append("Version Info: ");
        sBld.append(BouncyCastleFipsProvider.getInfoString());
        sBld.append(newLine);

        sBld.append("FIPS Ready Status: ");
        sBld.append(FipsStatus.getStatusMessage());
        sBld.append(newLine);

        NativeServices nativeServices = CryptoServicesRegistrar.getNativeServices();

        if (all || nativeServices.isEnabled())
        {
            if (all || nativeServices.isSupported())
            {
                sBld.append("Native Ready Status: ");
                sBld.append(nativeServices.getStatusMessage());
                sBld.append(newLine);
                sBld.append("Native Variant: ");
                sBld.append(nativeServices.getVariant());
                sBld.append(newLine);
                sBld.append("Native Build Date: ");
                sBld.append(nativeServices.getBuildDate());
                sBld.append(newLine);
            }
            if (nativeServices.isEnabled())
            {
                sBld.append("Native Support: ");
                sBld.append(getNativeFeatureString(nativeServices));
                sBld.append(newLine);
            }
        }

        if (all)
        {
            sBld.append(getVerboseStatusMessage(nativeServices));    // includes newlines
        }

        if (all)
        {

            String[][] result = nativeServices.getVariantSelectionMatrix();
            if (result.length >0)
            {
                sBld.append(newLine);
                sBld.append("CPU Features and Variant availability.");
                sBld.append(newLine);
                sBld.append("--------------------------------------------------------------------------------");
                sBld.append(newLine);
                sBld.append(pad("Variant", 10));
                sBld.append(pad("CPU features + or -:", 50));
                sBld.append(pad("Supported", 20));

                sBld.append(newLine);
                sBld.append("--------------------------------------------------------------------------------");
                sBld.append(newLine);
                for (String[] parts : result)
                {

                    String title = pad(parts[0], 10);
                    String cpuFeatures = "";
                    for (int t = 1; t < parts.length - 1; t++)
                    {
                        cpuFeatures += parts[t];
                        cpuFeatures += " ";
                    }
                    cpuFeatures = pad(cpuFeatures.trim(), 50);

                    String status = parts[parts.length - 1];

                    sBld.append(title);
                    sBld.append(cpuFeatures);
                    sBld.append(status);
                    sBld.append(newLine);
                }

                sBld.append(newLine);
            }
        }

        sBld.append("Module SHA-256 HMAC: " + Strings.fromByteArray(Hex.encode(FipsStatus.getModuleHMAC())));
        sBld.append(newLine);

        return sBld.toString();
    }

    private static String getVerboseStatusMessage(NativeServices nativeServices)
    {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);

        pw.println("Native Libs Available: " + nativeServices.isSupported());
        pw.println("Native Libs Installed: " + nativeServices.isInstalled());
        pw.println("Native Status Message: " + nativeServices.getStatusMessage());
        pw.close();

        return sw.toString();
    }

    private static String getNativeFeatureString(NativeServices nativeServices)
    {
        return String.join(" ", nativeServices.getFeatureSet());
    }

    private static String pad(String left, int len)
    {
        StringBuilder sb = new StringBuilder();
        sb.append(left);
        for (int t = 0; t < len - left.length(); t++)
        {
            sb.append(" ");
        }
        return sb.toString();
    }

    private static byte[] calculateModuleHMAC(JarFile jarFile)
    {
        // this code is largely the standard approach to self verifying a JCE with some minor modifications. It will calculate
        // the SHA-256 HMAC on the classes.
        try
        {
            OutputMACCalculator hMacCalculator = new FipsSHS.MACOperatorFactory().createOutputMACCalculator(new SymmetricSecretKey(FipsSHS.Algorithm.SHA256_HMAC, Strings.toByteArray(CryptoServicesRegistrar.MODULE_HMAC_KEY)), FipsSHS.SHA256_HMAC);

            UpdateOutputStream mOut = hMacCalculator.getMACStream();

            // build an index to make sure we get things in the same order.
            Map<String, JarEntry> index = new TreeMap<String, JarEntry>();

            for (Enumeration<JarEntry> entries = jarFile.entries(); entries.hasMoreElements(); )
            {
                JarEntry jarEntry = entries.nextElement();

                // Skip directories, META-INF, and module-info.class meta-data
                if (skipEntry(jarEntry))
                {
                    continue;
                }

                index.put(jarEntry.getName(), jarEntry);
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
                byte[] encName = Strings.toUTF8ByteArray(jarEntry.getName());
                mOut.update((byte) 0x5B);   // '['
                mOut.update(encName, 0, encName.length);
                mOut.update(Pack.longToBigEndian(jarEntry.getSize()), 0, 8);
                mOut.update((byte) 0x5D);    // ']'

                // contents
                int n;
                while ((n = is.read(buf, 0, buf.length)) != -1)
                {
                    mOut.update(buf, 0, n);
                }
                is.close();
            }

            mOut.update((byte) 0x5B);   // '['
            byte[] encName = Strings.toUTF8ByteArray("END");
            mOut.update(encName, 0, encName.length);
            mOut.update((byte) 0x5D);    // ']'

            mOut.close();

            return hMacCalculator.getMAC();
        }
        catch (Exception e)
        {
            return new byte[32];
        }
    }

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

    private static void runTests()
    {
        for (String cls : classes)
        {
            if (!FipsStatus.isErrorStatus())
            {
                loadClass(cls);
            }
        }

        // trigger tests of native services if available - entropy related tests are
        // done continuously.
        NativeServices nativeServices = CryptoServicesRegistrar.getNativeServices();
        if (nativeServices.isEnabled() && nativeServices.isSupported())
        {
            SymmetricKey aesKey = new SymmetricSecretKey(FipsAES.ALGORITHM, Hex.decode("000102030405060708090a0b0c0d0e0f"));

            FipsAES.OperatorFactory fact = new FipsAES.OperatorFactory();
            if (nativeServices.hasService(NativeServices.AES_ECB))
            {
                fact.createOutputEncryptor(aesKey, FipsAES.ECB);
            }
            if (nativeServices.hasService(NativeServices.AES_CBC))
            {
                fact.createOutputEncryptor(aesKey, FipsAES.CBC.withIV(Hex.decode("000102030405060708090a0b0c0d0e0f")));
            }
            if (nativeServices.hasService(NativeServices.AES_CFB))
            {
                fact.createOutputEncryptor(aesKey, FipsAES.CFB128.withIV(Hex.decode("000102030405060708090a0b0c0d0e0f")));
            }
            if (nativeServices.hasService(NativeServices.AES_CTR))
            {
                fact.createOutputEncryptor(aesKey, FipsAES.CTR.withIV(Hex.decode("000102030405060708090a0b0c0d0e0f")));
            }

            FipsAES.AEADOperatorFactory aeadFact = new FipsAES.AEADOperatorFactory();

            if (nativeServices.hasService(NativeServices.AES_GCM))
            {
                aeadFact.createOutputAEADEncryptor(aesKey, FipsAES.GCM.withIV(Hex.decode("000102030405060708090a0b")));
            }

            if (nativeServices.hasService(NativeServices.SHA2))
            {
                new FipsSHS.OperatorFactory<FipsSHS.Parameters>().createOutputDigestCalculator(FipsSHS.SHA256);
            }

            if (nativeServices.hasService(NativeServices.DRBG) || nativeServices.hasService(NativeServices.NRBG))
            {
                CryptoServicesRegistrar.getDefaultEntropySourceProvider().get(256);
            }
        }
    }

    private static void loadClass(String className)
    {
        try
        {
            Class.forName(className);
        }
        catch (ExceptionInInitializerError e)
        {
            throw e;
        }
        catch (ClassNotFoundException e)
        {
            throw new IllegalStateException("Unable to initialize module: " + e.getMessage(), e);
        }
    }
}