package org.bouncycastle.crypto.internal.pqc.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.asymmetric.AsymmetricLMSPublicKey;
import org.bouncycastle.crypto.fips.FipsLMS;
import org.bouncycastle.crypto.fips.FipsStatus;
import org.bouncycastle.crypto.internal.AsymmetricCipherKeyPair;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Well-formedness checks on LMS / HSS public key parsing, RFC 8554:
 * unknown typecodes and out-of-range level counts must be rejected with a
 * clean exception (sec. 5.3 / 6), and a byte[] encoding must be consumed
 * exactly (sec. 5.3, "If the public key is not exactly 24 + m bytes long,
 * return INVALID"). An HSS signature byte[] encoding must also be consumed
 * exactly (CVE-2026-58060).
 */
public class PublicKeyParseTests
{
    /**
     * Loading FipsLMS installs the LMS digest provider and runs the module's LMS verify KAT,
     * which parses its HSS public key and signature through the (now exact-consumption) byte[]
     * entry points - the module must still come up ready.
     */
    @BeforeClass
    public static void initModule()
    {
        Assert.assertTrue(FipsStatus.isReady());
        Assert.assertNotNull(FipsLMS.ALGORITHM);
        Assert.assertTrue(FipsStatus.isReady());
    }

    // lms_sha256_n32_h5 (5) / sha256_n32_w8 (4), I = 16 bytes, T[1] = 32 bytes.
    private static byte[] validLmsPublicKey()
    {
        return Composer.compose()
            .u32str(LMSigParameters.lms_sha256_n32_h5.getType())
            .u32str(LMOtsParameters.sha256_n32_w8.getType())
            .bytes(new byte[16])
            .bytes(new byte[32])
            .build();
    }

    private static byte[] validHssPublicKey(int l)
    {
        return Composer.compose().u32str(l).bytes(validLmsPublicKey()).build();
    }

    @Test
    public void testValidKeysParse()
        throws Exception
    {
        LMSPublicKeyParameters lmsKey = LMSPublicKeyParameters.getInstance(validLmsPublicKey());
        Assert.assertEquals(LMSigParameters.lms_sha256_n32_h5, lmsKey.getSigParameters());
        Assert.assertEquals(LMOtsParameters.sha256_n32_w8, lmsKey.getOtsParameters());

        HSSPublicKeyParameters hssKey = HSSPublicKeyParameters.getInstance(validHssPublicKey(1));
        Assert.assertEquals(1, hssKey.getL());
        Assert.assertEquals(lmsKey, hssKey.getLMSPublicKey());

        Assert.assertEquals(8, HSSPublicKeyParameters.getInstance(validHssPublicKey(8)).getL());
    }

    @Test
    public void testUnknownLMSTypeCodeRejected()
    {
        byte[] enc = validLmsPublicKey();
        enc[3] = (byte)0xee;

        try
        {
            LMSPublicKeyParameters.getInstance(enc);
            Assert.fail("unknown LMS typecode accepted");
        }
        catch (IOException e)
        {
            Assert.assertEquals("unknown LMS type code: 238", e.getMessage());
        }
    }

    @Test
    public void testUnknownOtsTypeCodeRejected()
    {
        byte[] enc = validLmsPublicKey();
        enc[7] = (byte)0xee;

        try
        {
            LMSPublicKeyParameters.getInstance(enc);
            Assert.fail("unknown LM-OTS typecode accepted");
        }
        catch (IOException e)
        {
            Assert.assertEquals("unknown LM-OTS type code: 238", e.getMessage());
        }
    }

    @Test
    public void testUnknownTypeCodeRejectedViaHSS()
    {
        byte[] enc = validHssPublicKey(1);
        enc[7] = (byte)0xee;

        try
        {
            HSSPublicKeyParameters.getInstance(enc);
            Assert.fail("unknown LMS typecode accepted");
        }
        catch (IOException e)
        {
            Assert.assertEquals("unknown LMS type code: 238", e.getMessage());
        }
    }

    @Test
    public void testHssLevelCountRange()
        throws Exception
    {
        int[] badL = new int[]{ 0, 9, 99, -1, Integer.MAX_VALUE, Integer.MIN_VALUE };
        for (int i = 0; i != badL.length; i++)
        {
            try
            {
                HSSPublicKeyParameters.getInstance(validHssPublicKey(badL[i]));
                Assert.fail("HSS L value " + badL[i] + " accepted");
            }
            catch (IOException e)
            {
                Assert.assertEquals("L value of HSS public key out of range: " + badL[i], e.getMessage());
            }
        }
    }

    /**
     * Exploit shape: an attacker supplied HSS public key with L = 2^31 - 1, followed by a
     * 4 byte "signature" claiming Nspk = L - 1, drove HSSSignature to allocate an
     * LMSSignedPubKey[L - 1] array (OutOfMemoryError). The key must now be rejected at parse
     * time, before any signature can be processed against it.
     */
    @Test
    public void testOversizedLevelCountCannotDriveSignatureAllocation()
    {
        byte[] maliciousKey = validHssPublicKey(Integer.MAX_VALUE);
        byte[] maliciousSig = Pack.intToBigEndian(Integer.MAX_VALUE - 1);

        try
        {
            HSSPublicKeyParameters key = HSSPublicKeyParameters.getInstance(maliciousKey);

            key.generateLMSContext(maliciousSig);
            Assert.fail("HSS public key with L = " + Integer.MAX_VALUE + " accepted");
        }
        catch (IOException e)
        {
            Assert.assertEquals("L value of HSS public key out of range: " + Integer.MAX_VALUE, e.getMessage());
        }
    }

    /**
     * Same exploit through the public API: an X.509 SubjectPublicKeyInfo for
     * id-alg-hss-lms-hashsig carrying L = 2^31 - 1 must not yield a usable key.
     */
    @Test
    public void testOversizedLevelCountRejectedViaSubjectPublicKeyInfo()
        throws Exception
    {
        byte[] spki = new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig),
            new DEROctetString(validHssPublicKey(Integer.MAX_VALUE))).getEncoded();
        byte[] maliciousSig = Pack.intToBigEndian(Integer.MAX_VALUE - 1);

        try
        {
            AsymmetricLMSPublicKey key = new AsymmetricLMSPublicKey(spki);

            key.getContextBasedVerifier().generateLMSContext(maliciousSig);
            Assert.fail("HSS public key with L = " + Integer.MAX_VALUE + " accepted");
        }
        catch (IllegalStateException e)
        {
            Assert.assertTrue(e.getCause() instanceof IOException);
            Assert.assertEquals("L value of HSS public key out of range: " + Integer.MAX_VALUE, e.getCause().getMessage());
        }

        // a well formed key still decodes through the same path.
        byte[] goodSpki = new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig),
            new DEROctetString(validHssPublicKey(2))).getEncoded();
        AsymmetricLMSPublicKey goodKey = new AsymmetricLMSPublicKey(goodSpki);
        Assert.assertEquals(2, goodKey.getL());
        Assert.assertTrue(Arrays.areEqual(validLmsPublicKey(), goodKey.getPublicData()));
    }

    @Test
    public void testTrailingDataRejected()
    {
        byte[] lmsTrailing = Arrays.append(validLmsPublicKey(), (byte)0);

        try
        {
            LMSPublicKeyParameters.getInstance(lmsTrailing);
            Assert.fail("trailing data after LMS public key accepted");
        }
        catch (IOException e)
        {
            Assert.assertEquals("unexpected data found after LMS public key", e.getMessage());
        }

        byte[] hssTrailing = Arrays.append(validHssPublicKey(2), (byte)0);

        try
        {
            HSSPublicKeyParameters.getInstance(hssTrailing);
            Assert.fail("trailing data after HSS public key accepted");
        }
        catch (IOException e)
        {
            Assert.assertEquals("unexpected data found after HSS public key", e.getMessage());
        }
    }

    /**
     * The stream entry points are used to read public keys embedded in larger
     * structures (HSS signature chains), so they must not require the stream
     * to be exhausted.
     */
    @Test
    public void testStreamParseLeavesTrailingData()
        throws Exception
    {
        byte[] two = Arrays.concatenate(validLmsPublicKey(), validLmsPublicKey());
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(two));

        LMSPublicKeyParameters first = LMSPublicKeyParameters.getInstance(in);
        LMSPublicKeyParameters second = LMSPublicKeyParameters.getInstance(in);
        Assert.assertEquals(first, second);
        Assert.assertEquals(0, in.available());
    }

    /**
     * A byte[] HSS signature encoding must be consumed exactly - trailing data is rejected,
     * while a well formed signature still parses and verifies.
     */
    @Test
    public void testHSSSignatureTrailingDataRejected()
        throws Exception
    {
        LMSParameters lmsParams = new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w8);

        HSSKeyPairGenerator kpGen = new HSSKeyPairGenerator();
        kpGen.init(new HSSKeyGenerationParameters(new LMSParameters[]{ lmsParams, lmsParams }, new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
        HSSPrivateKeyParameters privKey = (HSSPrivateKeyParameters)kp.getPrivate();
        HSSPublicKeyParameters pubKey = (HSSPublicKeyParameters)kp.getPublic();

        byte[] msg = new byte[]{ 'H', 'e', 'l', 'l', 'o' };

        HSSSigner signer = new HSSSigner();
        signer.init(true, privKey);
        byte[] sig = signer.generateSignature(msg);

        HSSSignature parsed = HSSSignature.getInstance(sig, pubKey.getL());
        Assert.assertTrue(Arrays.areEqual(sig, parsed.getEncoded()));

        HSSSigner verifier = new HSSSigner();
        verifier.init(false, pubKey);
        Assert.assertTrue(verifier.verifySignature(msg, sig));

        // the public key round trips through the byte[] (exact consumption) path.
        Assert.assertEquals(pubKey, HSSPublicKeyParameters.getInstance(pubKey.getEncoded()));

        byte[] sigTrailing = Arrays.append(sig, (byte)0);

        try
        {
            HSSSignature.getInstance(sigTrailing, pubKey.getL());
            Assert.fail("trailing data after HSS signature accepted");
        }
        catch (IOException e)
        {
            Assert.assertEquals("unexpected data found after HSS signature", e.getMessage());
        }

        try
        {
            pubKey.generateLMSContext(sigTrailing);
            Assert.fail("trailing data after HSS signature accepted");
        }
        catch (IOException e)
        {
            Assert.assertEquals("unexpected data found after HSS signature", e.getMessage());
        }
    }
}
