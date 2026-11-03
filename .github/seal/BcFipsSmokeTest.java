import java.io.File;
import java.io.InputStream;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import javax.crypto.*;
import javax.crypto.spec.*;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.EntropySource;
import org.bouncycastle.crypto.EntropySourceProvider;
import org.bouncycastle.crypto.NativeServices;
import org.bouncycastle.crypto.fips.FipsDRBG;
import org.bouncycastle.crypto.fips.FipsStatus;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

public class BcFipsSmokeTest
{
    interface Check { void run() throws Exception; }

    static int run = 0, passed = 0, failed = 0, skipped = 0;
    static Set<String> filter = null;
    static final Set<String> skipList = new LinkedHashSet<String>();   // -Dbcfips.skip.tests
    static final Set<String> seen = new HashSet<String>();
    static final String P = "BCFIPS";
    static String jarPath;
    static String nativeDir;
    static boolean nativeReady = false;

    /* A check named in -Dbcfips.skip.tests is not executed: reported as SKIP and counted in Skipped. */
    static boolean skipListed(String name)
    {
        if (!skipList.contains(name)) return false;
        skipped++;
        System.out.println("SKIP " + name + ": listed in -Dbcfips.skip.tests -- reason: "
            + System.getProperty("bcfips.skip.reason." + name, "(no reason given)"));
        return true;
    }

    static void check(String name, Check c)
    {
        seen.add(name);
        if (filter != null && !filter.contains(name)) return;
        if (skipListed(name)) return;
        run++;
        try
        {
            c.run();
            passed++;
            System.out.println("PASS " + name);
        }
        catch (Throwable t)
        {
            failed++;
            System.out.println("FAIL " + name + ": " + t);
            t.printStackTrace(System.out);
        }
    }

    /* A native-path check: runs only when the rebuilt native library is loaded and offers the service. */
    static void nativeCheck(String name, String[] services, Check c)
    {
        seen.add(name);
        if (filter != null && !filter.contains(name)) return;
        if (skipListed(name)) return;
        String reason = null;
        if (!nativeReady)
        {
            reason = "native library not loaded (" + CryptoServicesRegistrar.getNativeServices().getStatusMessage()
                + ", variant " + CryptoServicesRegistrar.getNativeServices().getVariant() + ")";
        }
        else
        {
            boolean any = false;
            for (String s : services) any |= CryptoServicesRegistrar.getNativeServices().hasService(s);
            if (!any) reason = "CPU/native variant lacks service " + Arrays.toString(services);
        }
        if (reason != null)
        {
            skipped++;
            System.out.println("SKIP " + name + ": " + reason);
            return;
        }
        check(name, c);
    }

    static void assertTrue(boolean b, String msg) { if (!b) throw new AssertionError(msg); }

    static String hex(byte[] b)
    {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }

    static byte[] unhex(String s)
    {
        byte[] r = new byte[s.length() / 2];
        for (int i = 0; i < r.length; i++) r[i] = (byte)Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return r;
    }

    static byte[] utf8(String s) throws Exception { return s.getBytes("UTF-8"); }

    static byte[] readAll(InputStream is) throws Exception
    {
        java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[8192]; int n;
        while ((n = is.read(buf)) > 0) bo.write(buf, 0, n);
        is.close();
        return bo.toByteArray();
    }

    static void digestKat(String alg, String in, String expected) throws Exception
    {
        String got = hex(MessageDigest.getInstance(alg, P).digest(utf8(in)));
        assertTrue(got.equals(expected), alg + " got " + got);
    }

    static void cipherKat(String transform, String key, String iv, String pt, String expected) throws Exception
    {
        SecretKeySpec k = new SecretKeySpec(unhex(key), "AES");
        Cipher enc = Cipher.getInstance(transform, P);
        if (iv == null) enc.init(Cipher.ENCRYPT_MODE, k);
        else if (transform.contains("GCM")) enc.init(Cipher.ENCRYPT_MODE, k, new GCMParameterSpec(128, unhex(iv)));
        else enc.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(unhex(iv)));
        String got = hex(enc.doFinal(unhex(pt)));
        assertTrue(got.equals(expected), transform + " got " + got);
        Cipher dec = Cipher.getInstance(transform, P);
        if (iv == null) dec.init(Cipher.DECRYPT_MODE, k);
        else if (transform.contains("GCM")) dec.init(Cipher.DECRYPT_MODE, k, new GCMParameterSpec(128, unhex(iv)));
        else dec.init(Cipher.DECRYPT_MODE, k, new IvParameterSpec(unhex(iv)));
        assertTrue(hex(dec.doFinal(unhex(expected))).equals(pt), transform + " decrypt mismatch");
    }

    static byte[] chunked(Cipher c, byte[] in) throws Exception
    {
        java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
        int[] sizes = { 1, 15, 16, 17, 31, 64, 255, 4096, 1000 };
        int off = 0, i = 0;
        while (off < in.length)
        {
            int n = Math.min(sizes[i++ % sizes.length], in.length - off);
            byte[] o = c.update(in, off, n);
            if (o != null) bo.write(o);
            off += n;
        }
        bo.write(c.doFinal());
        return bo.toByteArray();
    }

    public static void main(String[] args) throws Exception
    {
        jarPath = args[0];
        if (args.length > 1 && args[1].trim().length() > 0)
        {
            filter = new HashSet<String>(Arrays.asList(args[1].trim().split("\\s+")));
            if (filter.contains("BcFipsSmokeTest")) filter = null;
        }
        nativeDir = args.length > 2 ? args[2] : null;
        String skipProp = System.getProperty("bcfips.skip.tests", "").trim();
        if (skipProp.length() > 0) skipList.addAll(Arrays.asList(skipProp.split("[\\s,]+")));
        if (!skipList.isEmpty()) System.out.println("skip list (-Dbcfips.skip.tests): " + skipList);
        // CVE-2026-8149 regression check is registered only when the fix is in the tree (set by run.sh).
        final boolean cve8149Regression = Boolean.getBoolean("bcfips.cve8149.regression");
        final String forcedVariant = System.getProperty("org.bouncycastle.native.cpu_variant");
        final String expectedBuildTs = System.getProperty("bcfips.expected.build_ts");
        System.out.println("java.version=" + System.getProperty("java.version")
            + " java.vendor=" + System.getProperty("java.vendor")
            + (forcedVariant != null ? " forced native variant=" + forcedVariant : ""));

        Security.addProvider(new BouncyCastleFipsProvider());

        check("ProviderRegistration", new Check() { public void run() throws Exception {
            Provider p = Security.getProvider(P);
            assertTrue(p != null, "BCFIPS provider not registered");
            System.out.println("  provider: " + p.getInfo());
            String loc = BouncyCastleFipsProvider.class.getProtectionDomain().getCodeSource().getLocation().getPath();
            assertTrue(loc.endsWith(new File(jarPath).getName()), "provider loaded from unexpected location " + loc);
        }});

        check("FipsStatusReady", new Check() { public void run() throws Exception {
            boolean ready = FipsStatus.isReady();
            System.out.println("  status: " + FipsStatus.getStatusMessage());
            assertTrue(ready, "FipsStatus.isReady() returned false");
            assertTrue(!FipsStatus.isErrorStatus(), "module in error status");
        }});

        check("ModuleHmacMatchesJar", new Check() { public void run() throws Exception {
            JarFile jf = new JarFile(jarPath);
            JarEntry e = jf.getJarEntry("META-INF/HMAC.SHA256");
            assertTrue(e != null, "META-INF/HMAC.SHA256 missing from jar");
            String stored = new String(readAll(jf.getInputStream(e)), "US-ASCII").trim();
            jf.close();
            byte[] calc = FipsStatus.getModuleHMAC();
            assertTrue(calc != null, "getModuleHMAC() returned null");
            System.out.println("  HMAC.SHA256: " + stored);
            assertTrue(stored.equals(hex(calc)), "stored HMAC " + stored + " != computed " + hex(calc));
        }});

        check("JarNativeLibsAreRebuilt", new Check() { public void run() throws Exception {
            assertTrue(nativeDir != null, "no rebuilt native dir given");
            String[][] libs = { {"probe", "libbc-probe.so"}, {"avx", "libbc-fips-avx.so"},
                {"vaes", "libbc-fips-vaes.so"}, {"vaesf", "libbc-fips-vaesf.so"} };
            JarFile jf = new JarFile(jarPath);
            MessageDigest sha = MessageDigest.getInstance("SHA-256", P);
            for (String[] l : libs)
            {
                JarEntry e = jf.getJarEntry("native/linux/x86_64/" + l[0] + "/" + l[1]);
                assertTrue(e != null, l[1] + " missing from jar");
                byte[] inJar = readAll(jf.getInputStream(e));
                byte[] built = readAll(new java.io.FileInputStream(new File(nativeDir, l[0] + "/" + l[1])));
                System.out.println("  " + l[0] + "/" + l[1] + " sha256 " + hex(sha.digest(inJar)));
                assertTrue(Arrays.equals(inJar, built), l[1] + " in jar is not the freshly compiled library");
            }
            jf.close();
        }});

        check("NativeServicesLoaded", new Check() { public void run() throws Exception {
            NativeServices ns = CryptoServicesRegistrar.getNativeServices();
            System.out.println("  native status=" + ns.getStatusMessage() + " variant=" + ns.getVariant()
                + " libraryIdent=" + ns.getLibraryIdent() + " supported=" + ns.isSupported()
                + " installed=" + ns.isInstalled() + " enabled=" + ns.isEnabled());
            StringBuilder supported = new StringBuilder();
            for (String[] row : ns.getVariantSelectionMatrix())
            {
                System.out.println("  variant matrix: " + Arrays.toString(row));
                if (row.length > 0 && "Variant supported".equals(row[row.length - 1]))
                    supported.append(' ').append(row[0].toLowerCase());
            }
            System.out.println("SUPPORTED_NATIVE_VARIANTS=" + supported.toString().trim());
            if ("none".equals(ns.getVariant()))
            {
                System.out.println("  CPU offers no native variant: native checks below will be skipped");
                return;
            }
            assertTrue("READY".equals(ns.getStatusMessage()), "native status " + ns.getStatusMessage());
            assertTrue(ns.isSupported() && ns.isInstalled() && ns.isEnabled(), "native not supported/installed/enabled");
            assertTrue(ns.getVariant() != null && ns.getVariant().equals(ns.getLibraryIdent()),
                "loaded library " + ns.getLibraryIdent() + " != selected variant " + ns.getVariant());
            if (forcedVariant != null)
                assertTrue(forcedVariant.equals(ns.getLibraryIdent()), "forced " + forcedVariant + " but loaded " + ns.getLibraryIdent());
            System.out.println("  native build date=" + ns.getBuildDate() + " features=" + ns.getFeatureSet());
            if (expectedBuildTs != null)
                assertTrue(expectedBuildTs.equals(ns.getBuildDate()), "native BUILD_TS " + ns.getBuildDate());
            nativeReady = true;
        }});

        nativeCheck("NativeEntropySource", new String[] { NativeServices.NRBG, NativeServices.DRBG }, new Check() { public void run() throws Exception {
            EntropySourceProvider esp = FipsDRBG.getDefaultEntropySourceProvider();
            EntropySource es = esp.get(256);
            System.out.println("  entropy source: " + es.getClass().getName() + " size=" + es.entropySize()
                + " predictionResistant=" + es.isPredictionResistant()
                + " NRBG(rdseed)=" + CryptoServicesRegistrar.getNativeServices().hasService(NativeServices.NRBG)
                + " DRBG(rdrand)=" + CryptoServicesRegistrar.getNativeServices().hasService(NativeServices.DRBG));
            assertTrue(es.getClass().getName().endsWith("NativeEntropySource"), "not the native entropy source");
            assertTrue(es.entropySize() == 256, "entropySize " + es.entropySize());
            byte[] a = es.getEntropy(), b = es.getEntropy();
            assertTrue(a.length == 32 && b.length == 32, "unexpected entropy lengths " + a.length + "/" + b.length);
            assertTrue(!Arrays.equals(a, new byte[32]) && !Arrays.equals(b, new byte[32]), "all-zero entropy");
            assertTrue(!Arrays.equals(a, b), "identical entropy blocks");
            byte[] odd = esp.get(8 * 13).getEntropy();
            assertTrue(odd.length == 13, "non-multiple-of-8 entropy length " + odd.length);
            byte[] big = esp.get(8 * 1024).getEntropy();
            int[] counts = new int[256];
            for (byte x : big) counts[x & 0xff]++;
            int max = 0; for (int c : counts) max = Math.max(max, c);
            assertTrue(max < 64, "entropy byte distribution degenerate (max bucket " + max + ")");
        }});

        nativeCheck("NativeDRBG", new String[] { NativeServices.NRBG, NativeServices.DRBG }, new Check() { public void run() throws Exception {
            byte[] nonce = new byte[16];
            new SecureRandom().nextBytes(nonce);
            SecureRandom drbg = FipsDRBG.SHA512.fromEntropySource(FipsDRBG.getDefaultEntropySourceProvider())
                .setPersonalizationString(utf8("bc-fips sealed native DRBG")).build(nonce, true);
            byte[] x = new byte[64], y = new byte[64];
            drbg.nextBytes(x);
            drbg.nextBytes(y);
            assertTrue(!Arrays.equals(x, y) && !Arrays.equals(x, new byte[64]), "DRBG output degenerate");
            SecureRandom def = SecureRandom.getInstance("DEFAULT", P);
            byte[] z = new byte[48];
            def.nextBytes(z);
            assertTrue(!Arrays.equals(z, new byte[48]), "DEFAULT DRBG produced zeros");
        }});

        nativeCheck("NativeAESECBKAT", new String[] { NativeServices.AES_ECB }, new Check() { public void run() throws Exception {
            cipherKat("AES/ECB/NoPadding", "000102030405060708090a0b0c0d0e0f", null,
                "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a");          // FIPS-197 C.1
            cipherKat("AES/ECB/NoPadding", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", null,
                "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089");          // FIPS-197 C.3
        }});

        nativeCheck("NativeAESCBCKAT", new String[] { NativeServices.AES_CBC }, new Check() { public void run() throws Exception {
            cipherKat("AES/CBC/NoPadding", "2b7e151628aed2a6abf7158809cf4f3c", "000102030405060708090a0b0c0d0e0f",
                "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
                "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2");         // SP800-38A F.2.1
        }});

        nativeCheck("NativeAESCFBKAT", new String[] { NativeServices.AES_CFB }, new Check() { public void run() throws Exception {
            cipherKat("AES/CFB/NoPadding", "2b7e151628aed2a6abf7158809cf4f3c", "000102030405060708090a0b0c0d0e0f",
                "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
                "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b");         // SP800-38A F.3.13
        }});

        nativeCheck("NativeAESCTRKAT", new String[] { NativeServices.AES_CTR }, new Check() { public void run() throws Exception {
            cipherKat("AES/CTR/NoPadding", "2b7e151628aed2a6abf7158809cf4f3c", "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
                "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff");         // SP800-38A F.5.1
        }});

        nativeCheck("NativeAESGCMKAT", new String[] { NativeServices.AES_GCM }, new Check() { public void run() throws Exception {
            // McGrew/Viega GCM test case 3 (AES-128, 96-bit IV, no AAD). The FIPS provider refuses a
            // caller-chosen GCM nonce for encryption, so the KAT runs in the decrypt direction
            // (native GHASH/CTR + tag verification); encryption is covered by NativeAESBulkRoundtrip.
            SecretKeySpec k = new SecretKeySpec(unhex("feffe9928665731c6d6a8f9467308308"), "AES");
            byte[] iv = unhex("cafebabefacedbaddecaf888");
            byte[] ctTag = unhex("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"
                + "4d5c2af327cd64a62cf35abd2ba6fab4");
            Cipher dec = Cipher.getInstance("AES/GCM/NoPadding", P);
            dec.init(Cipher.DECRYPT_MODE, k, new GCMParameterSpec(128, iv));
            String got = hex(dec.doFinal(ctTag));
            assertTrue(got.equals("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"),
                "GCM KAT plaintext " + got);
            ctTag[ctTag.length - 1] ^= 1;
            dec.init(Cipher.DECRYPT_MODE, k, new GCMParameterSpec(128, iv));
            try { dec.doFinal(ctTag); throw new AssertionError("tampered GCM tag accepted"); }
            catch (AEADBadTagException expected) { }
        }});

        nativeCheck("NativeAESBulkRoundtrip", new String[] { NativeServices.AES_GCM, NativeServices.AES_CTR, NativeServices.AES_CBC, NativeServices.AES_CFB }, new Check() { public void run() throws Exception {
            SecureRandom r = SecureRandom.getInstance("DEFAULT", P);
            byte[] pt = new byte[65536 + 13];
            new Random(0x5ea1edL).nextBytes(pt);
            byte[] keyBytes = new byte[32];
            r.nextBytes(keyBytes);
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
            String[] transforms = { "AES/GCM/NoPadding", "AES/CTR/NoPadding", "AES/CBC/PKCS7Padding", "AES/CFB/NoPadding" };
            for (String t : transforms)
            {
                byte[] iv = new byte[t.contains("GCM") ? 12 : 16];
                r.nextBytes(iv);
                java.security.spec.AlgorithmParameterSpec spec = t.contains("GCM")
                    ? new GCMParameterSpec(128, iv) : new IvParameterSpec(iv);
                Cipher c = Cipher.getInstance(t, P);
                c.init(Cipher.ENCRYPT_MODE, key, spec);
                byte[] ct = c.doFinal(pt);
                if (!t.contains("GCM"))   // GCM nonces may not be reused for encryption
                {
                    c = Cipher.getInstance(t, P);
                    c.init(Cipher.ENCRYPT_MODE, key, spec);
                    byte[] ct2 = chunked(c, pt);
                    assertTrue(Arrays.equals(ct, ct2), t + " one-shot vs chunked ciphertext mismatch");
                }
                c = Cipher.getInstance(t, P);
                c.init(Cipher.DECRYPT_MODE, key, spec);
                assertTrue(Arrays.equals(pt, c.doFinal(ct)), t + " one-shot bulk decrypt mismatch");
                c = Cipher.getInstance(t, P);
                c.init(Cipher.DECRYPT_MODE, key, spec);
                byte[] dec;
                if (t.contains("GCM"))
                {
                    // GCM: whole ciphertext in ONE update() + doFinal(). The odd-chunked GCM decrypt is the
                    // separate NativeGCMOddChunkDecrypt check (CVE-2026-8149 regression check).
                    java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
                    byte[] o = c.update(ct, 0, ct.length);
                    if (o != null) bo.write(o);
                    bo.write(c.doFinal());
                    dec = bo.toByteArray();
                }
                else
                {
                    dec = chunked(c, ct);
                }
                assertTrue(Arrays.equals(pt, dec), t + " bulk decrypt mismatch");
                System.out.println("  " + t + " " + pt.length + " bytes ok");
            }
        }});

        if (cve8149Regression)
        {
        nativeCheck("NativeGCMOddChunkDecrypt", new String[] { NativeServices.AES_GCM }, new Check() { public void run() throws Exception {
            // CVE-2026-8149 regression check: the unpatched native gcm128w.c process_buffer_dec mishandles its
            // buffer when decrypt input arrives in odd-sized update() chunks -> "mac check in GCM failed".
            SecureRandom r = SecureRandom.getInstance("DEFAULT", P);
            byte[] pt = new byte[65536 + 13];
            new Random(0x5ea1edL).nextBytes(pt);
            byte[] keyBytes = new byte[32];
            r.nextBytes(keyBytes);
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
            byte[] iv = new byte[12];
            r.nextBytes(iv);
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding", P);
            c.init(Cipher.ENCRYPT_MODE, key, spec);
            byte[] ct = c.doFinal(pt);
            c = Cipher.getInstance("AES/GCM/NoPadding", P);
            c.init(Cipher.DECRYPT_MODE, key, spec);
            assertTrue(Arrays.equals(pt, chunked(c, ct)), "AES/GCM/NoPadding odd-chunked decrypt mismatch");
            System.out.println("  AES/GCM/NoPadding " + pt.length + " bytes odd-chunked decrypt ok");
        }});
        }

        nativeCheck("NativeSHA256Long", new String[] { NativeServices.SHA2 }, new Check() { public void run() throws Exception {
            byte[] a = new byte[1000000];
            Arrays.fill(a, (byte)'a');
            String got = hex(MessageDigest.getInstance("SHA-256", P).digest(a));
            assertTrue(got.equals("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"), "got " + got);
            MessageDigest md = MessageDigest.getInstance("SHA-256", P);
            for (int i = 0; i < a.length; i += 997) md.update(a, i, Math.min(997, a.length - i));
            assertTrue(hex(md.digest()).equals(got), "incremental SHA-256 mismatch");
        }});

        check("SHA256KAT", new Check() { public void run() throws Exception {
            digestKat("SHA-256", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        }});

        check("SHA512KAT", new Check() { public void run() throws Exception {
            digestKat("SHA-512", "abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
        }});

        check("SHA3_256KAT", new Check() { public void run() throws Exception {
            digestKat("SHA3-256", "abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
        }});

        check("HmacSHA256KAT", new Check() { public void run() throws Exception {
            // RFC 4231 test case 2
            Mac mac = Mac.getInstance("HmacSHA256", P);
            mac.init(new SecretKeySpec(utf8("Jefe"), "HmacSHA256"));
            String got = hex(mac.doFinal(utf8("what do ya want for nothing?")));
            assertTrue(got.equals("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"), "got " + got);
        }});

        check("AESGCMRoundtrip", new Check() { public void run() throws Exception {
            KeyGenerator kg = KeyGenerator.getInstance("AES", P);
            kg.init(256);
            SecretKey key = kg.generateKey();
            byte[] iv = new byte[12];
            SecureRandom.getInstance("DEFAULT", P).nextBytes(iv);
            byte[] pt = utf8("sealed bc-fips AES-GCM roundtrip");
            Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", P);
            enc.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            enc.updateAAD(utf8("aad"));
            byte[] ct = enc.doFinal(pt);
            Cipher dec = Cipher.getInstance("AES/GCM/NoPadding", P);
            dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            dec.updateAAD(utf8("aad"));
            assertTrue(Arrays.equals(pt, dec.doFinal(ct)), "GCM decrypt mismatch");
            ct[0] ^= 1;
            dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            dec.updateAAD(utf8("aad"));
            try { dec.doFinal(ct); throw new AssertionError("tampered GCM ciphertext accepted"); }
            catch (AEADBadTagException expected) { }
        }});

        check("AESCBCRoundtrip", new Check() { public void run() throws Exception {
            KeyGenerator kg = KeyGenerator.getInstance("AES", P);
            kg.init(128);
            SecretKey key = kg.generateKey();
            byte[] pt = utf8("sealed bc-fips AES-CBC PKCS7 roundtrip, more than one block");
            Cipher enc = Cipher.getInstance("AES/CBC/PKCS7Padding", P);
            enc.init(Cipher.ENCRYPT_MODE, key);
            byte[] ct = enc.doFinal(pt);
            Cipher dec = Cipher.getInstance("AES/CBC/PKCS7Padding", P);
            dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(enc.getIV()));
            assertTrue(Arrays.equals(pt, dec.doFinal(ct)), "CBC decrypt mismatch");
        }});

        check("RSASignVerify", new Check() { public void run() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", P);
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();
            byte[] msg = utf8("sealed bc-fips RSA");
            Signature s = Signature.getInstance("SHA256withRSA", P);
            s.initSign(kp.getPrivate());
            s.update(msg);
            byte[] sig = s.sign();
            Signature v = Signature.getInstance("SHA256withRSA", P);
            v.initVerify(kp.getPublic());
            v.update(msg);
            assertTrue(v.verify(sig), "RSA signature did not verify");
            v.initVerify(kp.getPublic());
            v.update(utf8("tampered"));
            assertTrue(!v.verify(sig), "RSA signature verified tampered message");
        }});

        check("ECDSASignVerify", new Check() { public void run() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", P);
            kpg.initialize(new ECGenParameterSpec("P-256"));
            KeyPair kp = kpg.generateKeyPair();
            byte[] msg = utf8("sealed bc-fips ECDSA");
            Signature s = Signature.getInstance("SHA256withECDSA", P);
            s.initSign(kp.getPrivate());
            s.update(msg);
            byte[] sig = s.sign();
            Signature v = Signature.getInstance("SHA256withECDSA", P);
            v.initVerify(kp.getPublic());
            v.update(msg);
            assertTrue(v.verify(sig), "ECDSA signature did not verify");
            v.initVerify(kp.getPublic());
            v.update(utf8("tampered"));
            assertTrue(!v.verify(sig), "ECDSA signature verified tampered message");
        }});

        check("ECDHAgreement", new Check() { public void run() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", P);
            kpg.initialize(new ECGenParameterSpec("P-256"));
            KeyPair a = kpg.generateKeyPair();
            KeyPair b = kpg.generateKeyPair();
            KeyAgreement ka = KeyAgreement.getInstance("ECCDH", P);
            ka.init(a.getPrivate());
            ka.doPhase(b.getPublic(), true);
            byte[] s1 = ka.generateSecret();
            KeyAgreement kb = KeyAgreement.getInstance("ECCDH", P);
            kb.init(b.getPrivate());
            kb.doPhase(a.getPublic(), true);
            byte[] s2 = kb.generateSecret();
            assertTrue(s1.length == 32 && Arrays.equals(s1, s2), "ECDH secrets differ");
        }});

        check("DRBGSecureRandom", new Check() { public void run() throws Exception {
            SecureRandom r = SecureRandom.getInstance("DEFAULT", P);
            byte[] x = new byte[32], y = new byte[32];
            r.nextBytes(x);
            r.nextBytes(y);
            assertTrue(!Arrays.equals(x, y), "DRBG produced identical blocks");
            assertTrue(!Arrays.equals(x, new byte[32]), "DRBG produced all-zero block");
            System.out.println("  algorithm: " + r.getAlgorithm());
        }});

        check("FipsStatusStillReady", new Check() { public void run() throws Exception {
            assertTrue(FipsStatus.isReady() && !FipsStatus.isErrorStatus(), "module left ready state");
        }});

        if (filter != null)
        {
            for (String f : filter)
            {
                if (!seen.contains(f)) { failed++; System.out.println("FAIL " + f + ": unknown check name"); }
            }
        }
        for (String s : skipList)   // a stale/typo'd skip-list entry must not pass silently
        {
            if (!seen.contains(s)) { failed++; System.out.println("FAIL " + s + ": unknown check name in -Dbcfips.skip.tests"); }
        }
        System.out.println("Tests run: " + run + ", Passed: " + passed + ", Failed: " + failed + ", Skipped: " + skipped);
        if (failed != 0 || run == 0) System.exit(1);
    }
}
