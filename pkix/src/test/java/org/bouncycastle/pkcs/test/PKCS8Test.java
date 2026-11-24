package org.bouncycastle.pkcs.test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.RSAPrivateCrtKeySpec;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfoBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;
import org.bouncycastle.util.Arrays;

/**
 * Tests around the PBES2 protection of PKCS#8 EncryptedPrivateKeyInfo structures.
 */
public class PKCS8Test
    extends TestCase
{
    private static final String PBE_MAX_ITERATION_COUNT = "org.bouncycastle.pbe.max_iteration_count";

    private static final char[] passwd = "hello".toCharArray();

    //
    // a private key we can wrap up - the modulus/exponents are the personal key
    // used by the other tests in this package.
    //
    private static final RSAPrivateCrtKeySpec privKeySpec = new RSAPrivateCrtKeySpec(
        new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
        new BigInteger("11", 16),
        new BigInteger("9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89", 16),
        new BigInteger("c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb", 16),
        new BigInteger("f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5", 16),
        new BigInteger("b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391", 16),
        new BigInteger("d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd", 16),
        new BigInteger("b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19", 16));

    private PrivateKeyInfo getPrivateKeyInfo()
        throws Exception
    {
        KeyFactory keyFact = KeyFactory.getInstance("RSA", "BC");
        PrivateKey privKey = keyFact.generatePrivate(privKeySpec);

        return PrivateKeyInfo.getInstance(privKey.getEncoded());
    }

    /**
     * Produce a PBES2/PBKDF2 protected private key using the writer's default iteration count.
     */
    private PKCS8EncryptedPrivateKeyInfo encryptPrivateKeyInfo()
        throws Exception
    {
        return new PKCS8EncryptedPrivateKeyInfoBuilder(getPrivateKeyInfo()).build(
            new JcePKCSPBEOutputEncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC)
                .setProvider("BC")
                .build(passwd));
    }

    /**
     * Rebuild an encrypted key with an attacker chosen PBKDF2 iteration count (and, optionally,
     * an explicit prf), re-encoding it so the guard is exercised against parsed key material.
     */
    private static PKCS8EncryptedPrivateKeyInfo withKdfParams(
        PKCS8EncryptedPrivateKeyInfo encInfo,
        ASN1Integer iterationCount,
        AlgorithmIdentifier prf)
        throws IOException
    {
        EncryptedPrivateKeyInfo info = encInfo.toASN1Structure();
        PBES2Parameters pbeParams = PBES2Parameters.getInstance(info.getEncryptionAlgorithm().getParameters());
        PBKDF2Params kdfParams = PBKDF2Params.getInstance(pbeParams.getKeyDerivationFunc().getParameters());

        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DEROctetString(kdfParams.getSalt()));
        v.add(iterationCount);
        if (prf != null)
        {
            v.add(prf);
        }

        PBES2Parameters rebuilt = new PBES2Parameters(
            new KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2, new DERSequence(v)),
            pbeParams.getEncryptionScheme());

        EncryptedPrivateKeyInfo tampered = new EncryptedPrivateKeyInfo(
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2, rebuilt), info.getEncryptedData());

        return new PKCS8EncryptedPrivateKeyInfo(tampered.getEncoded());
    }

    /**
     * A sane iteration count must still round-trip - the bound may not break normal use.
     */
    public void testPbkdf2RoundTrip()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfo encInfo = encryptPrivateKeyInfo();

        PrivateKeyInfo info = encInfo.decryptPrivateKeyInfo(
            new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build(passwd));

        assertTrue(Arrays.areEqual(getPrivateKeyInfo().getEncoded(), info.getEncoded()));
    }

    public void testPbkdf2IterationCountBound()
        throws Exception
    {
        // The PBES2/PBKDF2 iteration count travels in the unauthenticated encrypted-key container,
        // so it must be bounded before the key-derivation runs. Encrypt with the writer's default
        // count, then decrypt with the bound lowered below it: decryption must be rejected before
        // the derivation rather than honouring an attacker-chosen cost.
        PKCS8EncryptedPrivateKeyInfo encInfo = encryptPrivateKeyInfo();

        String old = System.getProperty(PBE_MAX_ITERATION_COUNT);
        System.setProperty(PBE_MAX_ITERATION_COUNT, "1");
        try
        {
            encInfo.decryptPrivateKeyInfo(
                new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build(passwd));
            fail("excessive PBKDF2 iteration count accepted");
        }
        catch (PKCSException e)
        {
            assertTrue("unexpected message: " + e.getMessage(), e.getMessage().indexOf("greater than 1") >= 0);
        }
        finally
        {
            restore(old);
        }
    }

    /**
     * With no override in place the built in bound must still reject an oversized count.
     */
    public void testPbkdf2IterationCountDefaultBound()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfo encInfo = withKdfParams(
            encryptPrivateKeyInfo(), new ASN1Integer(10000001), null);

        String old = System.getProperty(PBE_MAX_ITERATION_COUNT);
        System.clearProperty(PBE_MAX_ITERATION_COUNT);
        try
        {
            encInfo.decryptPrivateKeyInfo(
                new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build(passwd));
            fail("excessive PBKDF2 iteration count accepted");
        }
        catch (PKCSException e)
        {
            assertTrue("unexpected message: " + e.getMessage(),
                e.getMessage().indexOf("greater than 10000000") >= 0);
        }
        finally
        {
            restore(old);
        }
    }

    /**
     * The explicit-prf branch of the PBES2 decryptor must be bounded as well.
     */
    public void testPbkdf2IterationCountBoundWithPrf()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfo encInfo = withKdfParams(
            encryptPrivateKeyInfo(), new ASN1Integer(10000001),
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, DERNull.INSTANCE));

        PBES2Parameters pbeParams = PBES2Parameters.getInstance(
            encInfo.toASN1Structure().getEncryptionAlgorithm().getParameters());
        assertFalse(PBKDF2Params.getInstance(pbeParams.getKeyDerivationFunc().getParameters()).isDefaultPrf());

        String old = System.getProperty(PBE_MAX_ITERATION_COUNT);
        System.clearProperty(PBE_MAX_ITERATION_COUNT);
        try
        {
            encInfo.decryptPrivateKeyInfo(
                new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build(passwd));
            fail("excessive PBKDF2 iteration count accepted");
        }
        catch (PKCSException e)
        {
            assertTrue("unexpected message: " + e.getMessage(),
                e.getMessage().indexOf("greater than 10000000") >= 0);
        }
        finally
        {
            restore(old);
        }
    }

    /**
     * A count that does not even fit in an int must be rejected rather than silently truncated.
     */
    public void testPbkdf2OversizedIterationCount()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfo encInfo = withKdfParams(
            encryptPrivateKeyInfo(), new ASN1Integer(BigInteger.valueOf(2).pow(40)), null);

        try
        {
            encInfo.decryptPrivateKeyInfo(
                new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build(passwd));
            fail("oversized PBKDF2 iteration count accepted");
        }
        catch (PKCSException e)
        {
            assertTrue("unexpected message: " + e.getMessage(),
                e.getMessage().indexOf("invalid iteration count") >= 0);
        }
    }

    /**
     * A count of 2^32 + 10000001 truncates to 10000001 when read with intValue(), so a bound
     * applied to the truncated int would be bypassed - the count has to be checked as it was
     * encoded.
     */
    public void testPbkdf2TruncatedIterationCount()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfo encInfo = withKdfParams(
            encryptPrivateKeyInfo(),
            new ASN1Integer(BigInteger.valueOf(2).pow(32).add(BigInteger.valueOf(10000001))), null);

        try
        {
            encInfo.decryptPrivateKeyInfo(
                new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build(passwd));
            fail("truncated PBKDF2 iteration count accepted");
        }
        catch (PKCSException e)
        {
            assertTrue("unexpected message: " + e.getMessage(),
                e.getMessage().indexOf("invalid iteration count") >= 0);
        }
    }

    public void testPbkdf2NegativeIterationCount()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfo encInfo = withKdfParams(
            encryptPrivateKeyInfo(), new ASN1Integer(BigInteger.valueOf(-1)), null);

        try
        {
            encInfo.decryptPrivateKeyInfo(
                new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build(passwd));
            fail("negative PBKDF2 iteration count accepted");
        }
        catch (PKCSException e)
        {
            assertTrue("unexpected message: " + e.getMessage(),
                e.getMessage().indexOf("invalid iteration count") >= 0);
        }
    }

    /**
     * The OpenSSL flavoured PKCS#8 decryptor reads the same unauthenticated parameters, so it
     * carries the same bound.
     */
    public void testOpenSSLPbkdf2IterationCountBound()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfo encInfo = encryptPrivateKeyInfo();

        String old = System.getProperty(PBE_MAX_ITERATION_COUNT);
        System.setProperty(PBE_MAX_ITERATION_COUNT, "1");
        try
        {
            encInfo.decryptPrivateKeyInfo(
                new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider("BC").build(passwd));
            fail("excessive PBKDF2 iteration count accepted");
        }
        catch (PKCSException e)
        {
            assertTrue("unexpected message: " + e.getMessage(), e.getMessage().indexOf("greater than 1") >= 0);
        }
        finally
        {
            restore(old);
        }
    }

    public void testOpenSSLPbkdf2IterationCountDefaultBound()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfo encInfo = withKdfParams(
            encryptPrivateKeyInfo(), new ASN1Integer(10000001), null);

        String old = System.getProperty(PBE_MAX_ITERATION_COUNT);
        System.clearProperty(PBE_MAX_ITERATION_COUNT);
        try
        {
            encInfo.decryptPrivateKeyInfo(
                new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider("BC").build(passwd));
            fail("excessive PBKDF2 iteration count accepted");
        }
        catch (PKCSException e)
        {
            assertTrue("unexpected message: " + e.getMessage(),
                e.getMessage().indexOf("greater than 10000000") >= 0);
        }
        finally
        {
            restore(old);
        }
    }

    public void testOpenSSLPbkdf2OversizedIterationCount()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfo encInfo = withKdfParams(
            encryptPrivateKeyInfo(), new ASN1Integer(BigInteger.valueOf(2).pow(40)), null);

        try
        {
            encInfo.decryptPrivateKeyInfo(
                new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider("BC").build(passwd));
            fail("oversized PBKDF2 iteration count accepted");
        }
        catch (PKCSException e)
        {
            assertTrue("unexpected message: " + e.getMessage(),
                e.getMessage().indexOf("invalid iteration count") >= 0);
        }
    }

    private static void restore(String old)
    {
        if (old == null)
        {
            System.clearProperty(PBE_MAX_ITERATION_COUNT);
        }
        else
        {
            System.setProperty(PBE_MAX_ITERATION_COUNT, old);
        }
    }

    public static void main(String[] args)
    {
        junit.textui.TestRunner.run(suite());
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("PKCS8 Tests");

        suite.addTestSuite(PKCS8Test.class);

        return new BCTestSetup(suite);
    }
}
