// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import org.xbill.DNS.utils.base16;
import org.xbill.DNS.utils.base32;

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

public class NSEC3Record extends Record
{
  public static final byte SHA1_DIGEST_ID = 1;

  private boolean          AOFlag;
  private byte             hashAlg;
  private int              iterations;
  private byte[]           salt;
  private byte[]           next;
  private int              types[];

  NSEC3Record()
  {
  }

  Record getObject()
  {
    return new NSEC3Record();
  }

  /**
   * Creates an NSEC Record from the given data.
   * 
   * @param next The following name in an ordered list of the zone
   * @param types An array containing the types present.
   */
  public NSEC3Record(Name name, int dclass, long ttl, boolean AOFlag,
      byte hashAlg, int iterations, byte[] salt, byte[] next, int[] types)
  {
    super(name, Type.NSEC3, dclass, ttl);
    this.AOFlag = AOFlag;
    this.hashAlg = hashAlg;
    this.iterations = iterations;

    this.salt = new byte[salt.length];
    System.arraycopy(salt, 0, this.salt, 0, salt.length);

    if (next != null)
    {
      this.next = new byte[next.length];
      System.arraycopy(next, 0, this.next, 0, next.length);
    }

    for (int i = 0; i < types.length; i++)
    {
      Type.check(types[i]);
    }
    this.types = new int[types.length];
    System.arraycopy(types, 0, this.types, 0, types.length);
    Arrays.sort(this.types);
  }

  private int[] listToArray(List list)
  {
    int size = list.size();
    int[] array = new int[size];
    for (int i = 0; i < size; i++)
    {
      array[i] = ((Integer) list.get(i)).intValue();
    }
    return array;
  }

  void rrFromWire(DNSInput in) throws IOException
  {
    int first = in.readU8();
    AOFlag = (first & 0x80) != 0;
    hashAlg = (byte) (first & 0x7F);
    iterations = in.readU8() << 24 | in.readU16();

    int salt_length = in.readU8();
    salt = in.readByteArray(salt_length);

    int next_len = 20; // FIXME: should figure this out from the hashAlg.
    next = in.readByteArray(next_len);

    int lastbase = -1;
    List list = new ArrayList();
    while (in.remaining() > 0)
    {
      if (in.remaining() < 2)
        throw new WireParseException("invalid bitmap descriptor");
      int mapbase = in.readU8();
      if (mapbase < lastbase)
        throw new WireParseException("invalid ordering");
      int maplength = in.readU8();
      if (maplength > in.remaining())
        throw new WireParseException("invalid bitmap");
      for (int i = 0; i < maplength; i++)
      {
        int current = in.readU8();
        if (current == 0) continue;
        for (int j = 0; j < 8; j++)
        {
          if ((current & (1 << (7 - j))) == 0) continue;
          int typecode = mapbase * 256 + +i * 8 + j;
          list.add(Mnemonic.toInteger(typecode));
        }
      }
    }
    types = listToArray(list);
  }

  void rdataFromString(Tokenizer st, Name origin) throws IOException
  {
    int aoflag = st.getUInt8();
    AOFlag = (aoflag != 0);
    hashAlg = (byte) st.getUInt8(); // FIXME: check this for validity.
    iterations = (int) st.getUInt32();
    String salt_hex = st.getString();
    if (salt_hex.equals("0") || salt_hex.equals("00"))
    {
      salt = null;
    }
    else
    {
      salt = base16.fromString(salt_hex);
    }

    String next_base32 = st.getString();
    next = base32.fromString(next_base32);

    List list = new ArrayList();
    while (true)
    {
      Tokenizer.Token t = st.get();
      if (!t.isString()) break;
      int type = Type.value(t.value);
      if (type < 0)
      {
        throw st.exception("Invalid type: " + t.value);
      }
      list.add(Mnemonic.toInteger(type));
    }
    st.unget();
    types = listToArray(list);
    Arrays.sort(types);
  }

  /** Converts rdata to a String */
  String rrToString()
  {
    StringBuffer sb = new StringBuffer();
    sb.append(AOFlag ? '1' : '0');
    sb.append(' ');
    sb.append(hashAlg);
    sb.append(' ');
    sb.append(iterations);
    sb.append(salt == null ? "0" : base16.toString(salt));
    sb.append(' ');
    sb.append(base32.toString(next).toLowerCase());

    for (int i = 0; i < types.length; i++)
    {
      sb.append(" ");
      sb.append(Type.string(types[i]));
    }
    return sb.toString();
  }

  /** Returns the next hash */
  public byte[] getNext()
  {
    return next;
  }

  /** Set the next field.*/
  // Note: it is typical for implementations to have to set the 'next' field
  // after creating the record.
  public void setNext(byte[] next)
  {
    if (next == null)
    {
      this.next = null;
      return;
    }
    this.next = new byte[next.length];
    System.arraycopy(next, 0, this.next, 0, next.length);
  }
  
  public boolean getAuthoritativeOnlyFlag()
  {
    return AOFlag;
  }

  public byte getHashAlgorithm()
  {
    return hashAlg;
  }

  public int getIterations()
  {
    return iterations;
  }

  public byte[] getSalt()
  {
    return salt;
  }

  /** Returns the set of types defined for this name */
  public int[] getTypes()
  {
    int[] array = new int[types.length];
    System.arraycopy(types, 0, array, 0, types.length);
    return array;
  }

  /** Returns whether a specific type is in the set of types. */
  public boolean hasType(int type)
  {
    return (Arrays.binarySearch(types, type) >= 0);
  }

  static void mapToWire(DNSOutput out, int[] array, int mapbase,
      int mapstart, int mapend)
  {
    int mapmax = array[mapend - 1] & 0xFF;
    int maplength = (mapmax / 8) + 1;
    int[] map = new int[maplength];
    out.writeU8(mapbase);
    out.writeU8(maplength);
    for (int j = mapstart; j < mapend; j++)
    {
      int typecode = array[j];
      map[(typecode & 0xFF) / 8] |= (1 << (7 - typecode % 8));
    }
    for (int j = 0; j < maplength; j++)
    {
      out.writeU8(map[j]);
    }
  }

  void rrToWire(DNSOutput out, Compression c, boolean canonical)
  {
    out.writeU8((AOFlag ? 0x80 : 0) | (hashAlg & 0x7F));
    out.writeU8((iterations >> 16) & 0xFF);
    out.writeU16(iterations & 0xFFFF);
    out.writeU8(salt == null ? 0 : salt.length);
    if (salt != null) out.writeByteArray(salt);
    out.writeByteArray(next);

    if (types.length == 0) return;
    int mapbase = -1;
    int mapstart = -1;
    for (int i = 0; i < types.length; i++)
    {
      int base = types[i] >> 8;
      if (base == mapbase) continue;
      if (mapstart >= 0)
      {
        mapToWire(out, types, mapbase, mapstart, i);
      }
      mapbase = base;
      mapstart = i;
    }
    mapToWire(out, types, mapbase, mapstart, types.length);
  }

  public static byte[] hash(Name n, byte hash_algorithm, int iterations,
      byte[] salt) throws NoSuchAlgorithmException
  {
    MessageDigest md;

    switch (hash_algorithm)
    {
      case 1 :
        md = MessageDigest.getInstance("SHA1");
        break;
      default :
        throw new NoSuchAlgorithmException(
            "Unknown NSEC3 algorithm identifier: " + hash_algorithm);
    }
    
    // Construct our wire form.
    byte[] wire_name = n.toWireCanonical();
    byte[] res = wire_name; // for the first iteration.
    for (int i = 0; i <= iterations; i++)
    {
      // concatinate the salt, if it exists.
      if (salt != null)
      {
        byte[] concat = new byte[res.length + salt.length];
        System.arraycopy(res, 0, concat, 0, res.length);
        System.arraycopy(salt, 0, concat, res.length, salt.length);
        res = concat;
      }
      res = md.digest(res);
    }
    
    return res;
  }
}
