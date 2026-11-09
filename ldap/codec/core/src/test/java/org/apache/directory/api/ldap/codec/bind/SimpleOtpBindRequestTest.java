/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.directory.api.ldap.codec.bind;


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapEncoder;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.model.message.BindRequest;
import org.apache.directory.api.ldap.model.message.BindRequestImpl;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Tests the SimpleOTP authentication choice defined by
 * draft-joestr-wg-ldapsimpleotp.
 *
 * <pre>
 * AuthenticationChoice ::= CHOICE {
 *     ...
 *     simpleotp             [4] SimpleOTP }
 *
 * SimpleOTP ::= SEQUENCE {
 *     password              OCTET STRING,
 *     otpvalue              OCTET STRING }
 * </pre>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT )
public class SimpleOtpBindRequestTest extends AbstractCodecServiceTest
{
    /**
     * Test the decoding of a BindRequest with a SimpleOTP authentication choice
     */
    @Test
    public void testDecodeBindRequestSimpleOtp() throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x1E );
        stream.put( new byte[]
            {
                0x30, 0x1C,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x60, 0x17,               // CHOICE { ..., bindRequest BindRequest, ...
                                            // BindRequest ::= APPLICATION[0] SEQUENCE {
                    0x02, 0x01, 0x03,       // version INTEGER (1..127),
                    0x04, 0x00,             // name LDAPDN,
                    ( byte ) 0xA4, 0x10,    // authentication AuthenticationChoice
                                            // AuthenticationChoice ::= CHOICE { ..., simpleotp [4] SimpleOTP }
                                            // SimpleOTP ::= SEQUENCE {
                      0x04, 0x06,           // password OCTET STRING,
                        's', 'e', 'c', 'r', 'e', 't',
                      0x04, 0x06,           // otpvalue OCTET STRING }
                        '1', '2', '3', '4', '5', '6'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<BindRequest> container = new LdapMessageContainer<>( codec );

        // Decode the BindRequest PDU
        Asn1Decoder.decode( stream, container );

        // Check the decoded BindRequest
        BindRequest bindRequest = container.getMessage();

        assertEquals( 1, bindRequest.getMessageId() );
        assertTrue( bindRequest.isVersion3() );
        assertFalse( bindRequest.isSimple() );
        assertTrue( bindRequest.isSimpleOtp() );
        assertNull( bindRequest.getSaslMechanism() );
        assertEquals( "secret", Strings.utf8ToString( bindRequest.getCredentials() ) );
        assertEquals( "123456", Strings.utf8ToString( bindRequest.getOtpValue() ) );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, bindRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the encoding of a SimpleOTP BindRequest built from the model
     */
    @Test
    public void testEncodeBindRequestSimpleOtp() throws Exception
    {
        BindRequest bindRequest = new BindRequestImpl();
        bindRequest.setMessageId( 1 );
        bindRequest.setVersion3( true );
        bindRequest.setName( "" );
        bindRequest.setSimple( false );
        bindRequest.setSimpleOtp( true );
        bindRequest.setCredentials( "secret" );
        bindRequest.setOtpValue( "123456" );

        Asn1Buffer buffer = new Asn1Buffer();
        LdapEncoder.encodeMessage( buffer, codec, bindRequest );

        ByteBuffer encoded = buffer.getBytes();
        byte[] pdu = new byte[encoded.remaining()];
        encoded.get( pdu );

        ByteBuffer expected = ByteBuffer.allocate( 0x1E );
        expected.put( new byte[]
            {
                0x30, 0x1C,
                  0x02, 0x01, 0x01,
                  0x60, 0x17,
                    0x02, 0x01, 0x03,
                    0x04, 0x00,
                    ( byte ) 0xA4, 0x10,
                      0x04, 0x06,
                        's', 'e', 'c', 'r', 'e', 't',
                      0x04, 0x06,
                        '1', '2', '3', '4', '5', '6'
            } );

        assertArrayEquals( expected.array(), pdu );

        // And decode it back
        LdapMessageContainer<BindRequest> container = new LdapMessageContainer<>( codec );
        Asn1Decoder.decode( ByteBuffer.wrap( pdu ), container );

        BindRequest decoded = container.getMessage();
        assertTrue( decoded.isSimpleOtp() );
        assertFalse( decoded.isSimple() );
        assertEquals( "secret", Strings.utf8ToString( decoded.getCredentials() ) );
        assertEquals( "123456", Strings.utf8ToString( decoded.getOtpValue() ) );
    }


    /**
     * A SimpleOTP with an empty SEQUENCE must be rejected
     */
    @Test
    public void testDecodeBindRequestSimpleOtpEmpty()
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x0E );
        stream.put( new byte[]
            {
                0x30, 0x0C,
                  0x02, 0x01, 0x01,
                  0x60, 0x07,
                    0x02, 0x01, 0x03,
                    0x04, 0x00,
                    ( byte ) 0xA4, 0x00
            } );

        stream.flip();

        LdapMessageContainer<BindRequest> container = new LdapMessageContainer<>( codec );

        assertThrows( DecoderException.class, () -> Asn1Decoder.decode( stream, container ) );
    }
}
