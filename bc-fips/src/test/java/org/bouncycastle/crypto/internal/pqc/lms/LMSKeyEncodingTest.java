package org.bouncycastle.crypto.internal.pqc.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
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
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Encoding / parsing round trips for LMS and HSS public keys and HSS signatures (RFC 8554),
 * through the byte[] and stream entry points of LMSPublicKeyParameters, HSSPublicKeyParameters
 * and HSSSignature, and through the X.509 SubjectPublicKeyInfo path of AsymmetricLMSPublicKey.
 */
public class LMSKeyEncodingTest
{
    @BeforeClass
    public static void initModule()
    {
        Assert.assertTrue(FipsStatus.isReady());
        Assert.assertNotNull(FipsLMS.ALGORITHM);
        Assert.assertTrue(FipsStatus.isReady());
    }

    // lms_sha256_n32_h5 (5) / sha256_n32_w8 (4), I = 16 bytes, T[1] = 32 bytes.
    private static byte[] lmsPublicKey(byte fill)
    {
        byte[] i = new byte[16];
        byte[] t1 = new byte[32];
        java.util.Arrays.fill(i, fill);
        java.util.Arrays.fill(t1, (byte)(fill + 1));
        return Composer.compose()
            .u32str(LMSigParameters.lms_sha256_n32_h5.getType())
            .u32str(LMOtsParameters.sha256_n32_w8.getType())
            .bytes(i)
            .bytes(t1)
            .build();
    }

    private static byte[] hssPublicKey(int l, byte fill)
    {
        return Composer.compose().u32str(l).bytes(lmsPublicKey(fill)).build();
    }

    @Test
    public void testLmsPublicKeyRoundTrip()
        throws Exception
    {
        byte[] enc = lmsPublicKey((byte)7);
        Assert.assertEquals(4 + 4 + 16 + 32, enc.length);

        LMSPublicKeyParameters key = LMSPublicKeyParameters.getInstance(enc);
        Assert.assertEquals(LMSigParameters.lms_sha256_n32_h5, key.getSigParameters());
        Assert.assertEquals(LMOtsParameters.sha256_n32_w8, key.getOtsParameters());
        Assert.assertTrue(Arrays.areEqual(enc, key.getEncoded()));
        Assert.assertEquals(key, LMSPublicKeyParameters.getInstance(key.getEncoded()));
        Assert.assertNotEquals(key, LMSPublicKeyParameters.getInstance(lmsPublicKey((byte)9)));
    }

    @Test
    public void testHssPublicKeyRoundTrip()
        throws Exception
    {
        for (int l = 1; l <= 8; l++)
        {
            byte[] enc = hssPublicKey(l, (byte)l);
            HSSPublicKeyParameters key = HSSPublicKeyParameters.getInstance(enc);
            Assert.assertEquals(l, key.getL());
            Assert.assertEquals(LMSPublicKeyParameters.getInstance(lmsPublicKey((byte)l)), key.getLMSPublicKey());
            Assert.assertTrue(Arrays.areEqual(enc, key.getEncoded()));
            Assert.assertEquals(key, HSSPublicKeyParameters.getInstance(new ByteArrayInputStream(enc)));
        }
    }

    @Test
    public void testStreamParseOfConcatenatedKeys()
        throws Exception
    {
        byte[] two = Arrays.concatenate(lmsPublicKey((byte)1), lmsPublicKey((byte)2));
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(two));

        LMSPublicKeyParameters first = LMSPublicKeyParameters.getInstance(in);
        LMSPublicKeyParameters second = LMSPublicKeyParameters.getInstance(in);
        Assert.assertEquals(LMSPublicKeyParameters.getInstance(lmsPublicKey((byte)1)), first);
        Assert.assertEquals(LMSPublicKeyParameters.getInstance(lmsPublicKey((byte)2)), second);
        Assert.assertEquals(0, in.available());
    }

    @Test
    public void testSubjectPublicKeyInfoRoundTrip()
        throws Exception
    {
        byte[] spki = new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig),
            new DEROctetString(hssPublicKey(2, (byte)3))).getEncoded();

        AsymmetricLMSPublicKey key = new AsymmetricLMSPublicKey(spki);
        Assert.assertEquals(2, key.getL());
        Assert.assertTrue(Arrays.areEqual(lmsPublicKey((byte)3), key.getPublicData()));
        Assert.assertEquals(key, new AsymmetricLMSPublicKey(key.getEncoded()));
    }

    @Test
    public void testHssSignVerifyAndSignatureRoundTrip()
        throws Exception
    {
        LMSParameters lmsParams = new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w8);

        HSSKeyPairGenerator kpGen = new HSSKeyPairGenerator();
        kpGen.init(new HSSKeyGenerationParameters(new LMSParameters[]{ lmsParams, lmsParams }, new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
        HSSPrivateKeyParameters privKey = (HSSPrivateKeyParameters)kp.getPrivate();
        HSSPublicKeyParameters pubKey = (HSSPublicKeyParameters)kp.getPublic();
        Assert.assertEquals(2, pubKey.getL());

        byte[] msg = new byte[]{ 's', 'e', 'a', 'l', 'e', 'd' };

        HSSSigner signer = new HSSSigner();
        signer.init(true, privKey);
        byte[] sig = signer.generateSignature(msg);

        HSSSignature parsed = HSSSignature.getInstance(sig, pubKey.getL());
        Assert.assertTrue(Arrays.areEqual(sig, parsed.getEncoded()));
        Assert.assertEquals(parsed, HSSSignature.getInstance(new ByteArrayInputStream(sig), pubKey.getL()));

        HSSPublicKeyParameters decodedPub = HSSPublicKeyParameters.getInstance(pubKey.getEncoded());
        Assert.assertEquals(pubKey, decodedPub);

        HSSSigner verifier = new HSSSigner();
        verifier.init(false, decodedPub);
        Assert.assertTrue(verifier.verifySignature(msg, sig));

        LMSContext ctx = decodedPub.generateLMSContext(sig);
        ctx.update(msg, 0, msg.length);
        Assert.assertTrue(decodedPub.verify(ctx));

        byte[] tampered = Arrays.clone(msg);
        tampered[0] ^= 1;
        Assert.assertFalse(verifier.verifySignature(tampered, sig));
    }
}
