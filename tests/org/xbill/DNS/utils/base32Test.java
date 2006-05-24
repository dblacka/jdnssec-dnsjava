// -*- Java -*-
//
// Copyright (c) 2005, Matthew J. Rutherford <rutherfo@cs.colorado.edu>
// Copyright (c) 2005, University of Colorado at Boulder
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
// 
// * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
// 
// * Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the distribution.
// 
// * Neither the name of the University of Colorado at Boulder nor the
//   names of its contributors may be used to endorse or promote
//   products derived from this software without specific prior written
//   permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

package org.xbill.DNS.utils;

import junit.framework.TestCase;

public class base32Test extends TestCase
{
  public base32Test(String name)
  {
    super(name);
  }

  public void test_toString_empty()
  {
    byte[] data = new byte[0];
    String out = base32.toString(data);
    assertEquals("", out);
  }

  public void test_toString_basic1()
  {
    base32.usePadding(true);
    byte[] data = {0};
    String out = base32.toString(data);
    assertEquals("00======", out);
    base32.usePadding(false);
    out = base32.toString(data);
    assertEquals("00", out);
  }

  public void test_toString_basic2()
  {
    base32.usePadding(true);
    byte[] data = {0, 0};
    String out = base32.toString(data);
    assertEquals("0000====", out);
    base32.usePadding(false);
    out = base32.toString(data);
    assertEquals("0000", out);
  }

  public void test_toString_basic3()
  {
    base32.usePadding(true);    
    byte[] data = {0, 0, 1};
    String out = base32.toString(data);
    assertEquals("00002===", out);
    base32.usePadding(false);
    out = base32.toString(data);
    assertEquals("00002", out);
  }

  public void test_toString_basic4()
  {
    base32.usePadding(true);
    byte[] data = {(byte) 0xFC, 0, 0};
    String out = base32.toString(data);
    assertEquals("VG000===", out);
  }

  public void test_toString_basic5()
  {
    base32.usePadding(true);
    byte[] data = {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
    String out = base32.toString(data);
    assertEquals("VVVVU===", out);
  }

  public void test_toString_basic6()
  {
    base32.usePadding(true);
    byte[] data = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    String out = base32.toString(data);
    assertEquals("041061050O3GG28=", out);
  }

  public void test_formatString_empty1()
  {
    String out = base32.formatString(new byte[0], 5, "", false);
    assertEquals("", out);
  }

  public void test_formatString_shorter()
  {
    base32.usePadding(true);        
    byte[] in = {1, 2, 3, 4, 5, 6, 7, 8, 9}; // "041061050O3GG28=" (16 chars)
    String out = base32.formatString(in, 17, "", false);
    assertEquals("041061050O3GG28=", out);
  }

  public void test_formatString_sameLength()
  {
    base32.usePadding(true);    
    byte[] in = {1, 2, 3, 4, 5, 6, 7, 8, 9}; // "041061050O3GG28=" (16 chars)
    String out = base32.formatString(in, 16, "", false);
    assertEquals("041061050O3GG28=", out);
  }

  public void test_formatString_oneBreak()
  {
    base32.usePadding(true);    
    byte[] in = {1, 2, 3, 4, 5, 6, 7, 8, 9}; // "041061050O3GG28=" (16 chars)
    String out = base32.formatString(in, 14, "", false);
    assertEquals("041061050O3GG2\n8=", out);
  }

  public void test_formatString_twoBreaks1()
  {
    base32.usePadding(true);    
    byte[] in = {1, 2, 3, 4, 5, 6, 7, 8, 9}; // "041061050O3GG28=" (16 chars)
    String out = base32.formatString(in, 7, "", false);
    assertEquals("0410610\n50O3GG2\n8=", out);
    base32.usePadding(false);
    out = base32.formatString(in, 7, "", false);
    assertEquals("0410610\n50O3GG2\n8", out);
  }

  public void test_formatString_twoBreaks2()
  {
    base32.usePadding(true);    
    byte[] in = {1, 2, 3, 4, 5, 6, 7, 8, 9}; // "041061050O3GG28=" (16 chars)
    String out = base32.formatString(in, 6, "", false);
    assertEquals("041061\n050O3G\nG28=", out);
    base32.usePadding(false);
    out = base32.formatString(in, 6, "", false);
    assertEquals("041061\n050O3G\nG28", out);
  }

  public void test_formatString_shorterWithPrefix()
  {
    base32.usePadding(true);    
    byte[] in = {1, 2, 3, 4, 5, 6, 7, 8, 9}; // "041061050O3GG28="(16 chars)
    String out = base32.formatString(in, 16, "!_", false);
    assertEquals("!_041061050O3GG28=", out);
    base32.usePadding(false);
    out = base32.formatString(in, 16, "!_", false);
    assertEquals("!_041061050O3GG28", out);
  }

  public void test_formatString_sameLengthWithPrefix()
  {
    base32.usePadding(true);    
    byte[] in = {1, 2, 3, 4, 5, 6, 7, 8, 9}; // "041061050O3GG28=" (16 chars)
    String out = base32.formatString(in, 16, "!_", false);
    assertEquals("!_041061050O3GG28=", out);
  }

  public void test_formatString_oneBreakWithPrefix()
  {
    base32.usePadding(true);    
    byte[] in = {1, 2, 3, 4, 5, 6, 7, 8, 9}; // "041061050O3GG28=" (16 chars)
    String out = base32.formatString(in, 10, "!_", false);
    assertEquals("!_041061050O\n!_3GG28=", out);
  }

  public void test_formatString_twoBreaks1WithPrefix()
  {
    base32.usePadding(true);    
    byte[] in = {1, 2, 3, 4, 5, 6, 7, 8, 9}; // "041061050O3GG28=" (16 chars)
    String out = base32.formatString(in, 7, "!_", false);
    assertEquals("!_0410610\n!_50O3GG2\n!_8=", out);
  }

  public void test_formatString_twoBreaks2WithPrefix()
  {
    base32.usePadding(true);    
    byte[] in = {1, 2, 3, 4, 5, 6, 7, 8, 9}; // "041061050O3GG28=" (16 chars)
    String out = base32.formatString(in, 6, "!_", false);
    assertEquals("!_041061\n!_050O3G\n!_G28=", out);
  }

  public void test_formatString_shorterWithPrefixAndClose()
  {
    base32.usePadding(true);    
    byte[] in = {1, 2, 3, 4, 5, 6, 7, 8, 9}; // "041061050O3GG28=" (16 chars)
    String out = base32.formatString(in, 17, "!_", true);
    assertEquals("!_041061050O3GG28= )", out);
  }

  public void test_formatString_sameLengthWithPrefixAndClose()
  {
    base32.usePadding(true);    
    byte[] in = {1, 2, 3, 4, 5, 6, 7, 8, 9}; // "041061050O3GG28=" (16 chars)
    String out = base32.formatString(in, 16, "!_", true);
    assertEquals("!_041061050O3GG28= )", out);
  }

  public void test_formatString_oneBreakWithPrefixAndClose()
  {
    base32.usePadding(true);    
    byte[] in = {1, 2, 3, 4, 5, 6, 7, 8, 9}; // "041061050O3GG28=" (16 chars)
    String out = base32.formatString(in, 10, "!_", true);
    assertEquals("!_041061050O\n!_3GG28= )", out);
  }

  public void test_formatString_twoBreaks1WithPrefixAndClose()
  {
    base32.usePadding(true);    
    byte[] in = {1, 2, 3, 4, 5, 6, 7, 8, 9}; // "041061050O3GG28=" (16 chars)
    String out = base32.formatString(in, 7, "!_", true);
    assertEquals("!_0410610\n!_50O3GG2\n!_8= )", out);
  }

  public void test_formatString_twoBreaks2WithPrefixAndClose()
  {
    base32.usePadding(true);    
    byte[] in = {1, 2, 3, 4, 5, 6, 7, 8, 9}; // "041061050O3GG28=" (16 chars)
    String out = base32.formatString(in, 6, "!_", true);
    assertEquals("!_041061\n!_050O3G\n!_G28= )", out);
  }

  private void assertEquals(byte[] exp, byte[] act)
  {
    assertEquals(exp.length, act.length);
    for (int i = 0; i < exp.length; ++i)
    {
      assertEquals(exp[i], act[i]);
    }
  }

  public void test_fromString_empty1()
  {
    byte[] data = new byte[0];
    byte[] out = base32.fromString("");
    assertEquals(data, out);
  }

  public void test_fromString_basic1()
  {
    byte[] exp = {0x53};
    byte[] out = base32.fromString("AC");
    assertEquals(exp, out);
  }

  public void test_fromString_basic1_lc()
  {
    byte[] exp = {0x53};
    byte[] out = base32.fromString("ac");
    assertEquals(exp, out);
  }
  
  public void test_fromString_basic1_padded()
  {
    byte[] exp = {0x53};
    byte[] out = base32.fromString("AC======");
    assertEquals(exp, out);
  }
  public void test_fromString_basic2()
  {
    byte[] exp = {0x54, 0x57};
    byte[] out = base32.fromString("AHBG");
    assertEquals(exp, out);
    out = base32.fromString("ahbg");
    assertEquals(exp, out);
    out = base32.fromString("ahbg====");
    assertEquals(exp, out);
  }

  public void test_fromString_basic3()
  {
    byte[] exp = {0x64, 0x65, 0x66};
    byte[] out = base32.fromString("CHIMC");
    assertEquals(exp, out);
    out = base32.fromString("chImC");
    assertEquals(exp, out);
    out = base32.fromString("chimc===");
    assertEquals(exp, out);
  }

  public void test_fromString_basic4()
  {
    byte[] exp = {(byte) 0xFC, 0, 0};
    byte[] out = base32.fromString("vg000");
    assertEquals(exp, out);
    out = base32.fromString("VG000===");
    assertEquals(exp, out);
  }

  public void test_fromString_basic5()
  {
    byte[] exp = {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
    byte[] out = base32.fromString("VVVVU");
    assertEquals(out, exp);
  }

  public void test_fromString_basic6()
  {
    byte[] exp = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    byte[] out = base32.fromString("041061050O3GG28");
    assertEquals(out, exp);
    out = base32.fromString("041061050O3GG28=");
    assertEquals(out, exp);
  }

  public void test_fromString_invalid1()
  {
    byte[] out = base32.fromString("000");
    assertNull(out);
  }

  public void test_fromString_invalid2()
  {
    byte[] out = base32.fromString("000000");
    assertNull(out);
  }

  public void test_fromString_invalid3()
  {
    byte[] out = base32.fromString("0");
    assertNull(out);
  }

  public void test_fromString_invalid4()
  {
    byte[] out = base32.fromString("WX");
    assertNull(out);
  }

  public void test_fromString_invalid5()
  {
    byte[] out = base32.fromString("00=");
    assertNull(out);
  }

}
