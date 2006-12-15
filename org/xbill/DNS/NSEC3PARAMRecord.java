// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;

import org.xbill.DNS.utils.base16;

/**
 * Next SECure name 3 - this record contains the next hashed name in an
 * ordered list of hashed names in the zone, and a set of types for which
 * records exist for this name. The presence of this record in a response
 * signifies a negative response from a DNSSEC-signed zone.
 * 
 * This replaces the NSEC and NXT records, when used.
 * 
 * @author Brian Wellington
 * @author David Blacka
 */

public class NSEC3PARAMRecord extends Record
{
  private byte             hashAlg;
  private byte             flags;
  private int              iterations;
  private byte[]           salt;

  NSEC3PARAMRecord()
  {
  }

  Record getObject()
  {
    return new NSEC3PARAMRecord();
  }

  /**
   * Creates an NSEC3PARAM record from the given data.
   * 
   * @param name The ownername of the NSEC3 record (generally the zone name).
   * @param dclass The class.
   * @param ttl The TTL.
   * @param hashAlg The hash algorithm.
   * @param iterations The number of hash iterations.
   * @param salt The salt to use (may be null).
   */
  public NSEC3PARAMRecord(Name name, int dclass, long ttl, byte hashAlg, 
      byte flags, int iterations, byte[] salt)
  {
    super(name, Type.NSEC3PARAM, dclass, ttl);
    this.hashAlg = hashAlg;
    this.flags = flags;
    this.iterations = iterations;

    if (this.iterations < 0 || this.iterations >= NSEC3Record.MAX_ITERATIONS)
      throw new IllegalArgumentException("Invalid iterations value");

    if (salt != null)
    {
      if (salt.length > 255)
        throw new IllegalArgumentException("Invalid salt length");
      this.salt = new byte[salt.length];
      System.arraycopy(salt, 0, this.salt, 0, salt.length);
    }
  }

  void rrFromWire(DNSInput in) throws IOException
  {
    hashAlg = (byte) in.readU8();
    flags = (byte) in.readU8();
    iterations = in.readU16();

    int salt_length = in.readU8();
    if (salt_length > 0)
      salt = in.readByteArray(salt_length);
    else
      salt = null;

  }
  void rrToWire(DNSOutput out, Compression c, boolean canonical)
  {
    out.writeU8(hashAlg);
    out.writeU8(flags);
    out.writeU16(iterations);
    out.writeU8(salt == null ? 0 : salt.length);
    if (salt != null) out.writeByteArray(salt);
  }
  
  void rdataFromString(Tokenizer st, Name origin) throws IOException
  {
    // Note that the hash alg can either be a number or a mnemonic
    // Well, it can't really be a mnemonic, but we support it anyway.
    String hashAlgStr = st.getString();
    if (Character.isDigit(hashAlgStr.charAt(0)))
    {
      try
      {
        hashAlg = (byte) Long.parseLong(hashAlgStr);
      }
      catch (NumberFormatException e)
      {
        throw new IOException("expected an integer");
      }
    }
    else
    {
      hashAlg = NSEC3Record.mnemonicToAlg(hashAlgStr);
    }

    flags = (byte) st.getUInt8();
    iterations = st.getUInt16();
    String salt_hex = st.getString();
    if (salt_hex.equals("-") || salt_hex.equals("0"))
    {
      salt = null;
    }
    else
    {
      salt = base16.fromString(salt_hex);
      if (salt == null)
        throw st.exception("Invalid salt value: " + salt_hex);
      if (salt.length > 255)
        throw st.exception("Invalid salt value (too long): " + salt_hex);
    }
  }

  /** Converts rdata to a String */
  String rrToString()
  {
    StringBuffer sb = new StringBuffer();
    sb.append(hashAlg);
    sb.append(' ');
    sb.append(flags);
    sb.append(' ');
    sb.append(iterations);
    sb.append(' ');
    sb.append(salt == null ? "-" : base16.toString(salt));

    return sb.toString();
  }

  public byte getHashAlgorithm()
  {
    return hashAlg;
  }

  public byte getFlags()
  {
    return flags;
  }
  
  public int getIterations()
  {
    return iterations;
  }

  public byte[] getSalt()
  {
    return salt;
  }


}
