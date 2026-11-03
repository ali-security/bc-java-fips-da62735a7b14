package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.lang.ref.WeakReference;
import java.security.AccessController;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.EntropySource;
import org.bouncycastle.crypto.EntropySourceProvider;
import org.bouncycastle.crypto.SecureRandomProvider;
import org.bouncycastle.crypto.fips.FipsDRBG;
import org.bouncycastle.crypto.fips.FipsNative;
import org.bouncycastle.crypto.fips.FipsSecureRandom;
import org.bouncycastle.crypto.fips.FipsStatus;
import org.bouncycastle.crypto.util.BasicEntropySourceProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;

/**
 * The BC FIPS provider.
 * <p>
 * If no SecureRandom has been specified using CryptoServicesRegistrar.setSecureRandom() the provider class will generate a
 * FIPS compliant DRBG based on SHA-512. It is also possible to configure the DRBG by passing a string as a constructor
 * argument to the provider via code, or the java.security configuration file.
 * </p>
 * <p>
 * At the moment the configuration string is limited to setting the DRBG.The configuration string must always start
 * with "C:" and finish with "ENABLE{ALL};". The command for setting the actual DRBG type is DEFRND so a configuration
 * string requesting the use of a SHA1 DRBG would look like:
 * <pre>
 *         C:DEFRND[SHA1];ENABLE{ALL};
 *     </pre>
 * Possible values for the DRBG type are "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SHA512(224)", "SHA512(256)",
 * "HMACSHA1", "HMACSHA224", "HMACSHA256", "HMACSHA384", "HMACSHA512", "HMACSHA512(224)", "HMACSHA512(256)", "CTRAES128",
 * "CTRAES192", CTRAES256", and "CTRDESEDE".
 * </p>
 * <p>
 * The default DRBG is configured to be prediction resistant. In situations where the amount of entropy is constrained
 * the default DRBG can be configured to use an entropy pool based on a SHA-512 SP 800-90A DRBG. To configure this use:
 * <pre>
 *         C:HYBRID;ENABLE{ALL};
 *     </pre>
 * or include the string "HYBRID;" in the previous command string setting the DRBG. After initial seeding the entropy pool will
 * start a reseeding thread which it will begin polling once 20 samples have been taken since the last seeding and will do a reseed
 * as soon as new entropy bytes are returned.
 * </p>
 * <p>
 * Prediction resistance can also be turned off by specifying false in the DEFRND parameters. e.g.
 * <pre>
 *          C:DEFRND[SHA256,false];ENABLE{ALL};
 *     </pre>
 * or
 * <pre>
 *          C:DEFRND[false];ENABLE{ALL};
 *     </pre>
 * </p>
 * <p>
 * If "local" is specified a thread local will be used to store the DRBG instead.
 * <pre>
 *          C:DEFRND[SHA256,local];ENABLE{ALL};
 *     </pre>
 * or
 * <pre>
 *          C:DEFRND[local];ENABLE{ALL};
 *     </pre>
 * </p>
 * <p>
 * <b>Note</b>: if the provider is created by an "approved mode" thread, only FIPS approved algorithms will be available from it.
 * </p>
 */
public final class BouncyCastleFipsProvider
    extends Provider
{
    private static final String info = "BouncyCastle Security Provider (FIPS edition) v2.1.0";

    public static final String PROVIDER_NAME = "BCFIPS";

    public static String getInfoString()
    {
        return info;
    }

    private static final Map<String, FipsDRBG.Base> drbgTable = new HashMap<String, FipsDRBG.Base>();
    private static final Map<String, Integer> drbgStrengthTable = new HashMap<String, Integer>();

    static
    {
        drbgTable.put("SHA1", FipsDRBG.SHA1);
        drbgTable.put("SHA224", FipsDRBG.SHA224);
        drbgTable.put("SHA256", FipsDRBG.SHA256);
        drbgTable.put("SHA384", FipsDRBG.SHA384);
        drbgTable.put("SHA512", FipsDRBG.SHA512);
        drbgTable.put("SHA512(224)", FipsDRBG.SHA512_224);
        drbgTable.put("SHA512(256)", FipsDRBG.SHA512_256);

        drbgTable.put("HMACSHA1", FipsDRBG.SHA1_HMAC);
        drbgTable.put("HMACSHA224", FipsDRBG.SHA224_HMAC);
        drbgTable.put("HMACSHA256", FipsDRBG.SHA256_HMAC);
        drbgTable.put("HMACSHA384", FipsDRBG.SHA384_HMAC);
        drbgTable.put("HMACSHA512", FipsDRBG.SHA512_HMAC);
        drbgTable.put("HMACSHA512(224)", FipsDRBG.SHA512_224_HMAC);
        drbgTable.put("HMACSHA512(256)", FipsDRBG.SHA512_256_HMAC);

        drbgTable.put("CTRAES128", FipsDRBG.CTR_AES_128);
        drbgTable.put("CTRAES192", FipsDRBG.CTR_AES_192);
        drbgTable.put("CTRAES256", FipsDRBG.CTR_AES_256);
        drbgTable.put("CTRDESEDE", FipsDRBG.CTR_Triple_DES_168);

        drbgStrengthTable.put("SHA1", 128);
        drbgStrengthTable.put("SHA224", 192);
        drbgStrengthTable.put("SHA256", 256);
        drbgStrengthTable.put("SHA384", 256);
        drbgStrengthTable.put("SHA512", 256);
        drbgStrengthTable.put("SHA512(224)", 192);
        drbgStrengthTable.put("SHA512(256)", 256);

        drbgStrengthTable.put("HMACSHA1", 128);
        drbgStrengthTable.put("HMACSHA224", 192);
        drbgStrengthTable.put("HMACSHA256", 256);
        drbgStrengthTable.put("HMACSHA384", 256);
        drbgStrengthTable.put("HMACSHA512", 256);
        drbgStrengthTable.put("HMACSHA512(224)", 192);
        drbgStrengthTable.put("HMACSHA512(256)", 256);

        drbgStrengthTable.put("CTRAES128", 128);
        drbgStrengthTable.put("CTRAES192", 192);
        drbgStrengthTable.put("CTRAES256", 256);
        drbgStrengthTable.put("CTRDESEDE", 112);
    }

    private FipsDRBG.Base providerDefaultRandomBuilder = FipsDRBG.SHA512;
    private int providerDefaultSecurityStrength = 256;
    private boolean providerDefaultPredictionResistance = true;
    private boolean useThreadLocal = false;

    private boolean hybridSource = false;
    private final AtomicInteger providerDefaultRandomSecurityStrength = new AtomicInteger(providerDefaultSecurityStrength);
    private final SecureRandomProvider providerDefaultSecureRandomProvider;

    private Map<String, BcService> serviceMap = new ConcurrentHashMap<String, BcService>();
    private Map<String, EngineCreator> creatorMap = new HashMap<String, EngineCreator>();

    private final Map<ASN1ObjectIdentifier, AsymmetricKeyInfoConverter> keyInfoConverters = new HashMap<ASN1ObjectIdentifier, AsymmetricKeyInfoConverter>();

    private WeakReference<Set<Service>> serviceSetCache = new WeakReference<Set<Service>>(null);
    private SecureRandom entopySource = null;
    private Thread entropyThread = null;
    private EntropyDaemon entropyDaemon = null;

    /**
     * Base constructor - build a provider with the default configuration.
     */
    public BouncyCastleFipsProvider()
    {
        this(null);
    }

    /**
     * Constructor accepting a configuration string.
     *
     * @param config the config string.
     */
    public BouncyCastleFipsProvider(String config)
    {
        this(config, null);
    }

    /**
     * Constructor accepting a config string and a user defined source of entropy to be used for the providers locally
     * configured DRBG.
     *
     * @param config        the config string.
     * @param entropySource a SecureRandom which can act as an entropy source. (now ignored)
     */
    public BouncyCastleFipsProvider(String config, SecureRandom entropySource)
    {
        super(PROVIDER_NAME, 2.1000, getInfoString());

        this.entopySource = entropySource;
        // TODO: add support for file parsing, selective disable.

        if (config != null)
        {
            if (config.startsWith("C:") || config.startsWith("c:"))
            {
                processConfigString(Strings.toUpperCase(config));
            }
            else
            {
                throw new IllegalArgumentException("Unrecognized config string passed to " + PROVIDER_NAME + " provider.");
            }
        }

        if (useThreadLocal)
        {
            providerDefaultSecureRandomProvider = new ThreadLocalSecureRandomProvider();
        }
        else
        {
            providerDefaultSecureRandomProvider = new PooledSecureRandomProvider();
        }

        // must always be first (SecureRandom constructor)
        new ProvRandom().configure(this);

        new ProvSHS.SHA1().configure(this);
        new ProvSHS.SHA224().configure(this);
        new ProvSHS.SHA256().configure(this);
        new ProvSHS.SHA384().configure(this);
        new ProvSHS.SHA512().configure(this);
        new ProvSHS.SHA3_224().configure(this);
        new ProvSHS.SHA3_256().configure(this);
        new ProvSHS.SHA3_384().configure(this);
        new ProvSHS.SHA3_512().configure(this);
        new ProvSHS.SHAKE128().configure(this);
        new ProvSHS.SHAKE256().configure(this);
        new ProvKMAC().configure(this);
        if (!isDisabled("MD5"))
        {
            new ProvSecureHash.MD5().configure(this);  // TLS exception
        }
        new ProvPBESCRYPT().configure(this);

        if (!CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            new ProvSecureHash.GOST3411().configure(this);
            new ProvSecureHash.GOST3411_2012_256().configure(this);
            new ProvSecureHash.GOST3411_2012_512().configure(this);

            new ProvSecureHash.RIPEMD128().configure(this);
            new ProvSecureHash.RIPEMD160().configure(this);
            new ProvSecureHash.RIPEMD256().configure(this);
            new ProvSecureHash.RIPEMD320().configure(this);
            new ProvSecureHash.Tiger().configure(this);
            new ProvSecureHash.Whirlpool().configure(this);
        }

        new ProvDH().configure(this);
        new ProvDSA().configure(this);

        if (!Properties.isOverrideSet("org.bouncycastle.ec.disable"))
        {
            new ProvEC().configure(this);
        }

        new ProvRSA().configure(this);

        new ProvPBEPBKDF2().configure(this);

        if (!CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            new ProvPBEPBKDF1().configure(this);
            new ProvOpenSSLPBKDF().configure(this);
            new ProvPKCS12().configure(this);
        }

        new ProvAES().configure(this);
        new ProvDESede().configure(this);

        new ProvX509().configure(this);
        new ProvBCFKS().configure(this);
        new ProvFipsKS().configure(this);

        if (!CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            new ProvEdEC().configure(this);
            new ProvLMS().configure(this);
            new ProvDSTU4145().configure(this);
            new ProvElgamal().configure(this);
            new ProvGOST3410().configure(this);
            new ProvECGOST3410().configure(this);

            new ProvARIA().configure(this);
            new ProvBlowfish().configure(this);
            new ProvCAST5().configure(this);
            new ProvRC2().configure(this);
            new ProvGOST28147().configure(this);
            new ProvSEED().configure(this);
            new ProvCamellia().configure(this);
            new ProvChaCha20().configure(this);
            new ProvDES().configure(this);
            new ProvIDEA().configure(this);
            new ProvSerpent().configure(this);
            new ProvSHACAL2().configure(this);
            new ProvTwofish().configure(this);
            new ProvARC4().configure(this);
            new ProvSipHash().configure(this);
            new ProvPoly1305().configure(this);
        }

        if (!Properties.isOverrideSet("org.bouncycastle.pkix.disable_certpath"))
        {
            new ProvPKIX().configure(this);
        }

        if (Properties.isOverrideSet("org.bouncycastle.jca.enable_jks"))
        {
            new ProvJKS().configure(this);
        }
    }

    private EntropySourceProvider getDefaultEntropySourceProvider()
    {
        EntropySourceProvider entropySourceProvider;
        if (FipsNative.isEnabled())
        {
            entropySourceProvider = CryptoServicesRegistrar.getDefaultEntropySourceProvider();
        }
        else
        {
            entropySourceProvider = getEntropySourceProvider();
        }
        return entropySourceProvider;
    }

    // for Java 11
    public Provider configure(String configArg)
    {
        return new BouncyCastleFipsProvider(configArg);
    }

    private void processConfigString(String config)
    {
        String[] commands = config.substring(2).split(";");
        boolean enableAllFound = false;

        for (String command : commands)
        {
            if (command.startsWith("DEFRND"))
            {
                String rndConfig = extractString('[', ']', command);

                String rnd = null;
                String prOn = null;
                int commaPos = rndConfig.indexOf(",");
                if (commaPos > 0)
                {
                    rnd = rndConfig.substring(0, commaPos).trim();
                    prOn = rndConfig.substring(commaPos + 1).trim();
                }
                else
                {
                    if (rndConfig.equals("TRUE") || rndConfig.equals("FALSE"))
                    {
                        prOn = rndConfig;
                    }
                    else if (rndConfig.equals("LOCAL"))
                    {
                        useThreadLocal = true;
                    }
                    else
                    {
                        rnd = rndConfig;
                    }
                }
                if (prOn != null)
                {
                    providerDefaultPredictionResistance = Boolean.valueOf(prOn);
                }
                if (rnd != null)
                {
                    providerDefaultRandomBuilder = drbgTable.get(rnd);
                    if (drbgStrengthTable.containsKey(rnd))
                    {
                        providerDefaultSecurityStrength = drbgStrengthTable.get(rnd);
                    }
                    if (providerDefaultRandomBuilder == null)
                    {
                        throw new IllegalArgumentException("Unknown DEFRND - " + rnd + " - found in config string.");
                    }
                }
            }
            else if (command.startsWith("HYBRID"))
            {
                hybridSource = true;
                entropyDaemon = new EntropyDaemon();
                entropyThread = new Thread(entropyDaemon, "BC FIPS Entropy Daemon");
                entropyThread.setDaemon(true);
                entropyThread.start();
            }
            else if (command.startsWith("ENABLE"))
            {
                if ("ENABLE{ALL}".equals(command))
                {
                    enableAllFound = true;
                }
            }
        }

        if (!enableAllFound)
        {
            throw new IllegalArgumentException("No ENABLE command found in config string.");
        }
    }

    private String extractString(char startC, char endC, String command)
    {
        int start = command.indexOf(startC);
        int end = command.indexOf(endC);

        if (start < 0 || end < 0)
        {
            throw new IllegalArgumentException("Unable to parse config: ('" + startC + "', '" + endC + "') missing.");
        }

        return command.substring(start + 1, end);
    }

    int getProviderDefaultSecurityStrength()
    {
        return providerDefaultSecurityStrength;
    }

    FipsDRBG.Base getProviderDefaultRandomBuilder()
    {
        return providerDefaultRandomBuilder;
    }

    public SecureRandom getDefaultSecureRandom()
    {
        SecureRandom defRandom = CryptoServicesRegistrar.getSecureRandomIfSet(providerDefaultSecureRandomProvider);

        // we only allow this value to go down as we want to avoid people getting the wrong idea
        // about a provider produced random they might have.
        if (defRandom instanceof FipsSecureRandom)
        {
            int securityStrength = ((FipsSecureRandom)defRandom).getSecurityStrength();
            int currentSecurityStrength = providerDefaultRandomSecurityStrength.get();

            if (securityStrength < currentSecurityStrength)
            {
                synchronized (providerDefaultRandomSecurityStrength)
                {
                    if (securityStrength < providerDefaultRandomSecurityStrength.get())
                    {
                        providerDefaultRandomSecurityStrength.set(securityStrength);
                    }
                }
            }
        }
        else
        {
            providerDefaultRandomSecurityStrength.set(-1);     // unknown
        }

        return defRandom;
    }

    EntropySourceProvider getEntropySourceProvider()
    {
        // this has to be a lazy evaluation
        return AccessController.doPrivileged(new PrivilegedAction<EntropySourceProvider>()
        {
            public EntropySourceProvider run()
            {
                if (hybridSource)
                {
                    return new EntropySourceProvider()
                    {
                        @Override
                        public EntropySource get(int bitsRequired)
                        {
                            return new HybridEntropySource(entropyDaemon, bitsRequired, getCoreSecureRandom());
                        }
                    };
                }

                return new BasicEntropySourceProvider(getCoreSecureRandom(), true);
            }
        });
    }

    private SecureRandom getCoreSecureRandom()
    {
        return AccessController.doPrivileged(new PrivilegedAction<SecureRandom>()
        {
            public SecureRandom run()
            {
                try
                {
                    return SecureRandom.getInstanceStrong();
                }
                catch (Exception e)
                {
                    return new SecureRandom();  // fallback
                }
            }
        });
    }

    /**
     * Return the default random security strength.
     *
     * @return the security strength for the default SecureRandom the provider uses.
     */
    public int getDefaultRandomSecurityStrength()
    {
        return providerDefaultRandomSecurityStrength.get();
    }

    void addAttribute(String key, String attributeName, String attributeValue)
    {
        String attributeKey = key + " " + attributeName;
        if (containsKey(attributeKey))
        {
            throw new IllegalStateException("duplicate provider attribute key (" + attributeKey + ") found");
        }

        put(attributeKey, attributeValue);
    }

    void addAttribute(String type, ASN1ObjectIdentifier oid, String attributeName, String attributeValue)
    {
        String attributeKey = type + "." + oid + " " + attributeName;
        if (containsKey(attributeKey))
        {
            throw new IllegalStateException("duplicate provider attribute key (" + attributeKey + ") found");
        }

        put(attributeKey, attributeValue);
    }

    void addAttributes(String key, Map<String, String> attributes)
    {
        for (Map.Entry<String, String> attrEntry : attributes.entrySet())
        {
            addAttribute(key, attrEntry.getKey(), attrEntry.getValue());
        }
    }

    void addAttributes(String type, ASN1ObjectIdentifier oid, Map<String, String> attributes)
    {
        for (Map.Entry<String, String> attrEntry : attributes.entrySet())
        {
            addAttribute(type, oid, attrEntry.getKey(), attrEntry.getValue());
        }
    }

    void addAlgorithmImplementation(String key, String className, Map<String, String> attributes, EngineCreator creator)
    {
        if (containsKey(key))
        {
            throw new IllegalStateException("duplicate provider key (" + key + ") found");
        }

        addAttribute(key, "ImplementedIn", "Software");
        addAttributes(key, attributes);

        put(key, className);
        creatorMap.put(className, creator);
    }

    void addAlgorithmImplementation(String key, String className, EngineCreator creator)
    {
        if (containsKey(key))
        {
            throw new IllegalStateException("duplicate provider key (" + key + ") found");
        }

        addAttribute(key, "ImplementedIn", "Software");

        put(key, className);
        creatorMap.put(className, creator);
    }

    void addAlgorithmImplementation(String type, ASN1ObjectIdentifier oid, String className, EngineCreator creator)
    {
        String key1 = type + "." + oid;
        if (containsKey(key1))
        {
            throw new IllegalStateException("duplicate provider key (" + key1 + ") found");
        }

        addAttribute(type, oid, "ImplementedIn", "Software");

        put(key1, className);
        creatorMap.put(className, creator);

        addAlias(type, oid.getId(), "OID." + oid.getId());
    }

    void addAlgorithmImplementation(String type, ASN1ObjectIdentifier oid, String className, Map<String, String> attributes, EngineCreator creator)
    {
        String key1 = type + "." + oid;
        if (containsKey(key1))
        {
            throw new IllegalStateException("duplicate provider key (" + key1 + ") found");
        }

        addAttributes(type, oid, attributes);
        addAttribute(type, oid, "ImplementedIn", "Software");

        put(key1, className);
        creatorMap.put(className, creator);

        addAlias(type, oid.getId(), "OID." + oid.getId());
    }

    void addAlias(String key, String value)
    {
        if (containsKey(key))
        {
            throw new IllegalStateException("duplicate provider key (" + key + ") found");
        }

        put(key, value);
    }

    void addAlias(String type, String name, String... aliases)
    {
        if (!containsKey(type + "." + name))
        {
            throw new IllegalStateException("primary key (" + type + "." + name + ") not found");
        }

        for (String alias : aliases)
        {
            doPut("Alg.Alias." + type + "." + alias, name);
        }
    }

    void addAlias(String type, String name, ASN1ObjectIdentifier... oids)
    {
        if (!containsKey(type + "." + name))
        {
            throw new IllegalStateException("primary key (" + type + "." + name + ") not found");
        }

        for (ASN1ObjectIdentifier oid : oids)
        {
            doPut("Alg.Alias." + type + "." + oid, name);
            doPut("Alg.Alias." + type + ".OID." + oid, name);
        }
    }

    private void doPut(String key, String name)
    {
        if (containsKey(key))
        {
            throw new IllegalStateException("duplicate provider key (" + key + ") found");
        }

        put(key, name);
    }

    public final Service getService(String type, String algorithm)
    {
        String upperCaseAlgName = Strings.toUpperCase(algorithm);

        BcService service = serviceMap.get(type + "." + upperCaseAlgName);

        if (service == null)
        {
            String aliasString = "Alg.Alias." + type + ".";
            String realName = (String)this.get(aliasString + upperCaseAlgName);

            if (realName == null)
            {
                realName = upperCaseAlgName;
            }

            String className = (String)this.get(type + "." + realName);

            if (className == null)
            {
                return null;
            }

            String attributeKeyStart = type + "." + realName + " ";

            List<String> aliases = new ArrayList<String>();
            Map<String, String> attributes = new HashMap<String, String>();

            for (Map.Entry<Object, Object> entry : this.entrySet())
            {
                String sKey = (String)entry.getKey();
                if (sKey.startsWith(aliasString))
                {
                    if (entry.getValue().equals(algorithm))
                    {
                        aliases.add(sKey.substring(aliasString.length()));
                    }
                }
                if (sKey.startsWith(attributeKeyStart))
                {
                    attributes.put(sKey.substring(attributeKeyStart.length()), (String)entry.getValue());
                }
            }

            service = new BcService(this, type, upperCaseAlgName, className, aliases, getAttributeMap(attributes), creatorMap.get(className));

            BcService altService = serviceMap.putIfAbsent(type + "." + upperCaseAlgName, service);

            service = altService != null ? altService : service;
        }

        return service;
    }

    public final Set<Service> getServices()
    {
        Set<Service> bcServiceSet = serviceSetCache.get();

        if (bcServiceSet == null)
        {
            synchronized (this)
            {
                Set<Service> serviceSet = super.getServices();

                bcServiceSet = new LinkedHashSet<Service>();

                bcServiceSet.add(getService("SecureRandom", "DEFAULT"));
                bcServiceSet.add(getService("SecureRandom", "NONCEANDIV"));

                for (Service service : serviceSet)
                {
                    Service serv = getService(service.getType(), service.getAlgorithm());
                    if (serv != null)
                    {
                        bcServiceSet.add(serv);
                    }
                }

                bcServiceSet = Collections.unmodifiableSet(bcServiceSet);

                serviceSetCache = new WeakReference<Set<Service>>(bcServiceSet);
            }
        }

        return bcServiceSet;
    }

    void addKeyInfoConverter(ASN1ObjectIdentifier oid, AsymmetricKeyInfoConverter keyInfoConverter)
    {
        keyInfoConverters.put(oid, keyInfoConverter);
    }

    private boolean isDisabled(String algName)
    {
        String disabled = Properties.getPropertyValue("org.bouncycastle.disabledAlgorithms");

        return disabled != null && (disabled.indexOf(algName) >= 0);
    }

    private byte[] generatePersonalizationString(int rngIndex)
    {
        return Arrays.concatenate(Pack.intToBigEndian(rngIndex), Pack.longToBigEndian(Thread.currentThread().getId()), Pack.longToBigEndian(System.currentTimeMillis()));
    }

    private final Map<Map<String, String>, Map<String, String>> attributeMaps = new HashMap<Map<String, String>, Map<String, String>>();

    private synchronized Map<String, String> getAttributeMap(Map<String, String> attributeMap)
    {
        Map<String, String> attrMap = attributeMaps.get(attributeMap);
        if (attrMap != null)
        {
            return attrMap;
        }

        attributeMaps.put(attributeMap, attributeMap);

        return attributeMap;
    }

    PublicKey getPublicKey(SubjectPublicKeyInfo publicKeyInfo)
        throws IOException
    {
        AsymmetricKeyInfoConverter converter = keyInfoConverters.get(publicKeyInfo.getAlgorithm().getAlgorithm());

        if (converter == null)
        {
            return null;
        }

        return converter.generatePublic(publicKeyInfo);
    }

    PrivateKey getPrivateKey(PrivateKeyInfo privateKeyInfo)
        throws IOException
    {
        AsymmetricKeyInfoConverter converter = keyInfoConverters.get(privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm());

        if (converter == null)
        {
            return null;
        }

        return converter.generatePrivate(privateKeyInfo);
    }

    private static class BcService
        extends Service
    {
        private final EngineCreator creator;

        /**
         * Construct a new service.
         *
         * @param provider   the provider that offers this service
         * @param type       the type of this service
         * @param algorithm  the algorithm name
         * @param className  the name of the class implementing this service
         * @param aliases    List of aliases or null if algorithm has no aliases
         * @param attributes Map of attributes or null if this implementation
         *                   has no attributes
         * @throws NullPointerException if provider, type, algorithm, or
         *                              className is null
         */
        public BcService(Provider provider, String type, String algorithm, String className, List<String> aliases, Map<String, String> attributes, EngineCreator creator)
        {
            super(provider, type, algorithm, className, aliases, attributes);
            this.creator = creator;
        }

        public Object newInstance(Object constructorParameter)
            throws NoSuchAlgorithmException
        {
            try
            {
                FipsStatus.isReady();

                Object instance = creator.createInstance(constructorParameter);

                if (instance == null)
                {
                    throw new NoSuchAlgorithmException("No such algorithm in FIPS approved mode: " + getAlgorithm());
                }

                return instance;
            }
            catch (NoSuchAlgorithmException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new NoSuchAlgorithmException("Unable to invoke creator for " + getAlgorithm() + ": " + e.getMessage(), e);
            }
        }
    }

    private static class HybridEntropySource
        implements EntropySource
    {
        private final AtomicBoolean seedAvailable = new AtomicBoolean(false);
        private final AtomicInteger samples = new AtomicInteger(0);

        private final FipsSecureRandom drbg;
        private final SignallingEntropySource entropySource;
        private final int bytesRequired;

        HybridEntropySource(final EntropyDaemon entropyDaemon, final int bitsRequired, SecureRandom baseRandom)
        {
            bytesRequired = (bitsRequired + 7) / 8;
            // remember for the seed generator we need the correct security strength for SHA-512
            entropySource = new SignallingEntropySource(entropyDaemon, seedAvailable, baseRandom, 256);
            drbg = FipsDRBG.SHA512.fromEntropySource(new EntropySourceProvider()
                {
                    public EntropySource get(final int bitsRequired)
                    {
                        return entropySource;
                    }
                })
                .setPersonalizationString(Strings.toByteArray("Bouncy Castle Hybrid Entropy Source"))
                .build(baseRandom.generateSeed(32), false, null);     // 32 byte nonce
        }

        @Override
        public boolean isPredictionResistant()
        {
            return true;
        }

        @Override
        public byte[] getEntropy()
        {
            byte[] entropy = new byte[bytesRequired];

            // after 20 samples we'll start to check if there is new seed material.
            if (samples.getAndIncrement() > 20)
            {
                if (seedAvailable.getAndSet(false))
                {
                    samples.set(0);
                    drbg.reseed();
                }
                else
                {
                    entropySource.schedule();
                }
            }

            drbg.nextBytes(entropy);

            return entropy;
        }

        @Override
        public int entropySize()
        {
            return bytesRequired * 8;
        }

        private class SignallingEntropySource
            implements EntropySource
        {
            private final EntropyDaemon entropyDaemon;
            private final AtomicBoolean seedAvailable;
            private final SecureRandom baseRandom;
            private final int byteLength;
            private final AtomicReference entropy = new AtomicReference();
            private final AtomicBoolean scheduled = new AtomicBoolean(false);

            SignallingEntropySource(EntropyDaemon entropyDaemon, AtomicBoolean seedAvailable, SecureRandom baseRandom, int bitsRequired)
            {
                this.entropyDaemon = entropyDaemon;
                this.seedAvailable = seedAvailable;
                this.baseRandom = baseRandom;
                this.byteLength = (bitsRequired + 7) / 8;
            }

            public boolean isPredictionResistant()
            {
                return true;
            }

            public byte[] getEntropy()
            {
                byte[] seed = (byte[])entropy.getAndSet(null);

                if (seed == null || seed.length != byteLength)
                {
                    seed = baseRandom.generateSeed(byteLength);
                }
                else
                {
                    scheduled.set(false);
                }

                schedule();

                return seed;
            }

            void schedule()
            {
                if (!scheduled.getAndSet(true))
                {
                    entropyDaemon.addTask(new EntropyGatherer(byteLength, baseRandom, seedAvailable, entropy));
                }
            }

            public int entropySize()
            {
                return byteLength * 8;
            }
        }

    }

    static final int POOL_SIZE = getPoolSize(); // must be power of 2

    private static int getPoolSize()
    {
        String poolSize = Properties.getPropertyValue("org.bouncycastle.drbg.pool_size");

        int size;
        if (poolSize != null)
        {
            size = Integer.parseInt(poolSize);

            if (size < 2)
            {
                return 2;
            }
        }
        else
        {
            size = Runtime.getRuntime().availableProcessors() * 2;
        }

        return Integer.highestOneBit(size);  // size needs to be a power of 2.
    }

    private class PooledSecureRandomProvider
        implements SecureRandomProvider
    {
        private final AtomicReference<SecureRandom>[] providerDefaultRandom = new AtomicReference[POOL_SIZE];

        PooledSecureRandomProvider()
        {
            for (int i = 0; i != providerDefaultRandom.length; i++)
            {
                providerDefaultRandom[i] = new AtomicReference<SecureRandom>();
            }
        }

        public SecureRandom get()
        {
            // See SP 800-90A R1 8.6.7 for setting of Nonce - at least 1/2 security strength bits
            int rngIndex = (Thread.currentThread().hashCode() & (POOL_SIZE - 1)) % providerDefaultRandom.length;
            if (providerDefaultRandom[rngIndex].get() == null)
            {
                synchronized (providerDefaultRandom)
                {
                    if (providerDefaultRandom[rngIndex].get() == null)
                    {
                        EntropySourceProvider entropySourceProvider = getDefaultEntropySourceProvider();

                        EntropySource seedSource = entropySourceProvider.get((providerDefaultSecurityStrength / 2) + 1);

                        // we set providerDefault here as we end up recursing due to personalization string
                        providerDefaultRandom[rngIndex].compareAndSet(null, providerDefaultRandomBuilder
                            .fromEntropySource(entropySourceProvider)
                            .setPersonalizationString(generatePersonalizationString(rngIndex))
                            .build(seedSource.getEntropy(), providerDefaultPredictionResistance, Strings.toByteArray("Bouncy Castle FIPS Provider")));
                    }
                }
            }

            return providerDefaultRandom[rngIndex].get();
        }
    }

    private class ThreadLocalSecureRandomProvider
        implements SecureRandomProvider
    {
        final ThreadLocal<FipsSecureRandom> defaultRandoms = new ThreadLocal<FipsSecureRandom>();

        public SecureRandom get ()
        {
            // See SP 800-90A R1 8.6.7 for setting of Nonce - at least 1/2 security strength bits
            if (defaultRandoms.get() == null)
            {
                EntropySourceProvider entropySourceProvider = getDefaultEntropySourceProvider();
                EntropySource seedSource = entropySourceProvider.get((providerDefaultSecurityStrength / 2) + 1);

                // we set providerDefault here as we end up recursing due to personalization string
                defaultRandoms.set(providerDefaultRandomBuilder
                    .fromEntropySource(entropySourceProvider)
                    .setPersonalizationString(generatePersonalizationString((int)Thread.currentThread().getId()))
                    .build(seedSource.getEntropy(), providerDefaultPredictionResistance, Strings.toByteArray("Bouncy Castle FIPS Provider")));
            }

            return defaultRandoms.get();
        }
    }
}
