// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS.utils;

import java.io.*;
import java.util.Arrays;

/**
 * Routines for converting between Strings of base32-encoded data and arrays
 * of binary data.
 * 
 * @author Brian Wellington
 */

public class base32
{

  // This is alphabet described by RFC 3548
  private static final String Base32_3548 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  // This is the alphabet describted by RFC 2932
  private static final String Base32_2932 = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
  
  // This is the alphabet that will be used by default.
  private static String Base32 = Base32_2932;
  
  private base32()
  {
  }

  public static void setBase32Alphabet(boolean useRfc3548)
  {
    if (useRfc3548)
    {
      Base32 = Base32_3548;
    }
    else
    {
      Base32 = Base32_2932;
    }
  }
  
  /**
   * Convert binary data to a base32-encoded String
   * 
   * @param b An array containing binary data
   * @return A String containing the encoded data
   */
  public static String toString(byte[] b)
  {
    ByteArrayOutputStream os = new ByteArrayOutputStream();

    // each 40-bits (5 bytes) translates into 8 base32 characters.

    byte[] s = new byte[5];
    byte[] t = new byte[8];
    int j, k, nblocks, block_len, padding;

    nblocks = (b.length + 4) / 5;
    
    // for each block (including the last, incomplete block)
    for (int i = 0; i <  nblocks; i++)
    {
      // clear the array if we are in the last block.
      if (i == nblocks-1) Arrays.fill(s, (byte) 0);
      
      // copy the current block into our staging area. This allows us to
      // always work with a 5 byte block, even on the last block
      for (j = i * 5, k = 0; k < s.length && j < b.length; k++, j++)
      {
        s[k] = b[j];
      }

      // calculate our actual block length and passing length.
      block_len = (k != s.length) ? b.length % 5 : 5;
      padding = blockLenToPadding(block_len);

      // convert the 5 byte block into 8 characters (values 0-31).

      // upper 5 bits from first byte
      t[0] = (byte) ((s[0] >> 3) & 0x1F);
      // lower 3 bits from 1st byte, upper 2 bits from 2nd.
      t[1] = (byte) (((s[0] & 0x07) << 2) | ((s[1] >> 6) & 0x03));
      // bits 5-1 from 2nd.
      t[2] = (byte) ((s[1] >> 1) & 0x1F);
      // lower 1 bit from 2nd, upper 4 from 3rd
      t[3] = (byte) (((s[1] & 0x01) << 4) | ((s[2] >> 4) & 0x0F));
      // lower 4 from 3rd, upper 1 from 4th.
      t[4] = (byte) (((s[2] & 0x0F) << 1) | ((s[3] >> 7) & 0x01));
      // bits 6-2 from 4th
      t[5] = (byte) ((s[3] >> 2) & 0x1F);
      // lower 2 from 4th, upper 3 from 5th;
      t[6] = (byte) (((s[3] & 0x03) << 3) | ((s[4] >> 5) & 0x07));
      // lower 5 from 5th;
      t[7] = (byte) (s[4] & 0x1F);

      // write out the actual characters.
      for (int n = 0; n < t.length - padding; n++)
        os.write(Base32.charAt(t[n]));
      // write out the padding (if any)
      for (int n = t.length - padding; n < t.length; n++)
        os.write('=');
    }

    return new String(os.toByteArray());
  }

  /**
   * Formats data into a nicely formatted base32 encoded String
   * 
   * @param b An array containing binary data
   * @param lineLength The number of characters per line
   * @param prefix A string prefixing the characters on each line
   * @param addClose Whether to add a close parenthesis or not
   * @return A String representing the formatted output
   */
  public static String formatString(byte[] b, int lineLength, String prefix,
      boolean addClose)
  {
    String s = toString(b);
    StringBuffer sb = new StringBuffer();
    for (int i = 0; i < s.length(); i += lineLength)
    {
      sb.append(prefix);
      if (i + lineLength >= s.length())
      {
        sb.append(s.substring(i));
        if (addClose) sb.append(" )");
      }
      else
      {
        sb.append(s.substring(i, i + lineLength));
        sb.append("\n");
      }
    }
    return sb.toString();
  }

  /** Convert the block length into an amount of padding */
  static private int blockLenToPadding(int block_len)
  {
    switch (block_len)
    {
      case 0 :
      case 5 :
      default :
        return 0;
      case 1 :
        return 6;
      case 2 :
        return 4;
      case 3 :
        return 3;
      case 4 :
        return 1;

    }
  }

  /**
   * Convert the amount of padding in a 8-character block (i.e., the last 8
   * character block) to the length of the resultant byte block (between 1 and
   * 5).
   * 
   * @param chars_of_padding Number of characters of padding. In base 32, this
   *          is either 0, 1, 3, 4, or 6. No other values are valid.
   * @return The number of bytes actually in this block (1 through 5).
   */
  static private int paddingToBlockLen(int chars_of_padding)
  {
    switch (chars_of_padding)
    {
      case 6 :
        return 1;
      case 4 :
        return 2;
      case 3 :
        return 3;
      case 1 :
        return 4;
      case 0 :
        return 5;
      default :
        return -1;
    }
  }

  /**
   * Convert a base32-encoded String to binary data
   * 
   * @param str A String containing the encoded data
   * @return An array containing the binary data, or null if the string is
   *         invalid
   */
  public static byte[] fromString(String str)
  {
    ByteArrayOutputStream bs = new ByteArrayOutputStream();

    // Strip whitespace, upcase.
    byte[] raw = str.getBytes();
    for (int i = 0; i < raw.length; i++)
    {
      if (Character.isWhitespace((char) raw[i])) continue;
      bs.write((byte) Character.toUpperCase((char) raw[i]));
    }

    byte[] in = bs.toByteArray();

    bs.reset();
    DataOutputStream ds = new DataOutputStream(bs);

    short[] s = new short[8];
    int[] t = new int[5];
    int j, k, nblocks, block_len, padding; 
    
    nblocks = (in.length + 7) / 8;
    
    for (int i = 0; i < nblocks; i++)
    {
      if (i == nblocks - 1) Arrays.fill(s, (short) 0);
      padding = 0;
      // convert each char into the corresponding integer.
      for (j = i * 8, k = 0; j < in.length && k < s.length; j++, k++)
      {
        if (in[j] == '=')
        {
          padding = 8 - k;
          // now, if you want to be strict, when there is padding you might
          // insist that there be the *right amount* of padding.
          if (in.length % 8 != 0) return null;
          break;
        }
        s[k] = (short) Base32.indexOf(in[j]);
        if (s[k] < 0) return null; // invalid base32 character.
      }
      padding = (k != s.length) ? 8 - k : padding;
      block_len = paddingToBlockLen(padding);
      if (block_len < 0) return null; // invalid base32 length
      
      // all 5 bits of 1st, high 3 (of 5) of 2nd
      t[0] = (s[0] << 3) | s[1] >> 2;
      // lower 2 of 2nd, all 5 of 3rd, high 1 of 4th
      t[1] = ((s[1] & 0x03) << 6) | (s[2] << 1) | (s[3] >> 4);
      // lower 4 of 4th, high 4 of 5th
      t[2] = ((s[3] & 0x0F) << 4) | ((s[4] >> 1) & 0x0F);
      // lower 1 of 5th, all 5 of 6th, high 2 of 7th
      t[3] = (s[4] << 7) | (s[5] << 2) | (s[6] >> 3);
      // lower 3 of 7th, all of 8th
      t[4] = ((s[6] & 0x07) << 5) | s[7];

      try
      {
        for (j = 0; j < block_len; j++)
          ds.writeByte((byte) (t[j] & 0xFF));
      }
      catch (IOException e)
      {}
    }

    return bs.toByteArray();
  }

  public static void main(String[] args)
  {
    try
    {
      if (args.length == 1)
      {
        byte[] out = fromString(args[0]);
        System.out.print("byte[] exp = { ");
        for (int i = 0; i < out.length; i++)
        {
          int n = out[i] & 0xFF;
          System.out.print(n + ", ");
        }
        System.out.println("};");
        System.exit(0);
      }
      
      // convert arguments into a byte array.
      byte[] in = new byte[args.length];
      for (int i = 0; i < args.length; i++)
      {
        in[i] = (byte) (Integer.parseInt(args[i]) & 0xFF);
      }
      
      String s = toString(in);
      System.out.println("base 32: " + s);
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }
  }
}
