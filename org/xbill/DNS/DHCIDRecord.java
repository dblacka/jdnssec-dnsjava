// Copyright (c) 2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import org.xbill.DNS.utils.*;

/**
 * DHCID - DHCP Information Record; see RFC 4701.
 * 
 * @author Brian Wellington
 * @author David Blacka
 */

public class DHCIDRecord extends Record {

    private byte[] data;

    DHCIDRecord() {
    }

    Record getObject() {
        return new DHCIDRecord();
    }

    /**
     * Creates an DHCID Record from the given data.
     * 
     * @param data
     *            The opaque DHCID data.
     */
    public DHCIDRecord(Name name, int dclass, long ttl, byte[] data) {
        super(name, Type.DHCID, dclass, ttl);
        this.data = data;
    }

    void rrFromWire(DNSInput in) throws IOException {
        this.data = in.readByteArray(in.remaining());
    }

    void rdataFromString(Tokenizer st, Name origin) throws IOException {
        data = st.getBase64();
    }

    String rrToString() {
        StringBuffer sb = new StringBuffer();
        sb.append(base64.toString(data));
        return sb.toString();
    }

    void rrToWire(DNSOutput out, Compression c, boolean canonical) {
        out.writeByteArray(data);
    }

}
