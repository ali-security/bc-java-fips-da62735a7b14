package org.bouncycastle.crypto.fips;

import org.bouncycastle.util.Properties;

/**
 * Entropy constants for SP 800-90B. Can be set using "org.bouncycastle.entropy.factors"
 * which takes 3 numbers in the format of "&lt;int&gt;,&lt;int&gt;,&lt;float&gt;" being
 * the values for Stuck C, Adaptive C, and H.
 */
public class FipsEntropyConfig
{
    private static final int W = 512; // we expect more than 1 bit of entropy per sample.

    private static int C;
    private static int AdptC;
    private static float H;

    private static int retry;

    static
    {
        String factors = Properties.getPropertyValue("org.bouncycastle.entropy.factors");
        if (factors != null)
        {
            String[] splitFactors = factors.split(",");

            if (splitFactors.length != 3)
            {
                FipsStatus.moveToErrorStatus(new FipsOperationError("entropy factors needs to be <int>,<int>,<float>"));
            }

            try
            {
                C = Integer.parseInt(splitFactors[0].trim());
                AdptC = Integer.parseInt(splitFactors[1].trim());
                H = Float.parseFloat(splitFactors[2].trim());
            }
            catch (Exception e)
            {
                FipsStatus.moveToErrorStatus(new FipsOperationError("exception parsing entropy factors: " + e.getMessage(), e));
            }
        }
        else
        {
            C = 4;
            //
            // calculated using =1+CRITBINOM(W, POWER(2,(-H)),1-POWER(2,(-20)))  in Excel
            // where W = 512, H = 8.
            //
            AdptC = 13;
            H = 8.0f;
        }

        String ret = Properties.getPropertyValue("org.bouncycastle.entropy.retry");
        if (ret != null)
        {
            try
            {
                retry = Integer.parseInt(ret);
            }
            catch (Exception e)
            {
                FipsStatus.moveToErrorStatus(new FipsOperationError("exception parsing entropy retry: " + e.getMessage(), e));
            }
        }
        else
        {
            retry = 5;
        }
    }

    /**
     * Return the number of bits of entropy per byte of original noise.
     *
     * @return H, the amount of entropy in a byte.
     */
    public static float getH()
    {
        return H;
    }

    /**
     * Return the C value for the SP 800-90B, 4.4.1 isStuck() test.
     *
     * @return C.
     */
    public static int getStuckC()
    {
        return C;
    }

    /**
     * Return the C value for the SP 800-90B, 4.4.2 isProportionate() test.
     *
     * @return proportionate C.
     */
    public static int getAdaptiveProportionateC()
    {
        return AdptC;
    }

    public static int getAdaptiveProportionateW()
    {
        return W;
    }

    public static int getMaxRetries()
    {
        return retry;
    }
}
