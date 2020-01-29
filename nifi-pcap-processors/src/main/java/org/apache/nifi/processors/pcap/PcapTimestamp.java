/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.nifi.processors.pcap;

import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.expression.AttributeExpression;
import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.annotation.behavior.ReadsAttribute;
import org.apache.nifi.annotation.behavior.ReadsAttributes;
import org.apache.nifi.annotation.behavior.WritesAttribute;
import org.apache.nifi.annotation.behavior.WritesAttributes;
import org.apache.nifi.annotation.lifecycle.OnScheduled;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.SeeAlso;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.processor.exception.ProcessException;
import org.apache.nifi.processor.AbstractProcessor;
import org.apache.nifi.processor.ProcessContext;
import org.apache.nifi.processor.ProcessSession;
import org.apache.nifi.processor.ProcessorInitializationContext;
import org.apache.nifi.processor.Relationship;
import org.apache.nifi.processor.util.StandardValidators;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import io.pkts.PacketHandler;
import io.pkts.Pcap;
import io.pkts.buffer.Buffer;
import io.pkts.packet.Packet;
import io.pkts.packet.TCPPacket;
import io.pkts.packet.UDPPacket;
import io.pkts.protocol.Protocol;

@Tags({"example"})
@CapabilityDescription("Extracts the timestamp of a pcap file and adds it as a flowfile property.")
@SeeAlso({})
@ReadsAttributes({@ReadsAttribute(attribute="", description="")})
@WritesAttributes({@WritesAttribute(attribute="", description="")})
public class PcapTimestamp extends AbstractProcessor {

    ////////////////
    // PROPERTIES //
    ////////////////
	public static final PropertyDescriptor PROP_DATEFORMAT = new PropertyDescriptor
            .Builder().name("PROP_DATEFORMAT")
            .displayName("Date Format")
            .description("A string representing the format of the timestamp.")
            //.expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .required(false)
            //.sensitive(true)
            .defaultValue("yyyy.MM.dd HH:mm:ss.SSS")
            .addValidator(StandardValidators.createAttributeExpressionLanguageValidator(AttributeExpression.ResultType.STRING))
            .build();
    
    // Add all PropertyDescriptor objects to List
    public static final List<PropertyDescriptor> PROPERTIES = Collections.unmodifiableList(Arrays.asList(
    		PROP_DATEFORMAT
    		));
    
    // Relationships
    public static final Relationship REL_SUCCESS = new Relationship.Builder()
            .name("Success")
            .description("Any flowfile where the pcap timestamp was successfully extracted and added as a property.")
            .build();
    public static final Relationship REL_FAILURE = new Relationship.Builder()
            .name("Failure")
            .description("Any flowfile where the timestamp was unsuccessfully extracted.")
            .build();
    
    // Add all Relationship objects to Set
    public static final Set<Relationship> RELATIONSHIPS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
    		REL_SUCCESS,
    		REL_FAILURE
    		)));
    
    
    /////////////
    // METHODS //
    /////////////
    @Override
    protected void init(final ProcessorInitializationContext context) {

    }

    @Override
    public Set<Relationship> getRelationships() {
        return RELATIONSHIPS;
    }

    @Override
    public final List<PropertyDescriptor> getSupportedPropertyDescriptors() {
        return PROPERTIES;
    }

    @OnScheduled
    public void onScheduled(final ProcessContext context) {

    }

    @Override
    public void onTrigger(final ProcessContext context, final ProcessSession session) throws ProcessException {
    	
    	// Variable Properties
		final String dateFormat = context.getProperty(PROP_DATEFORMAT).getValue();
		
    	// Get FlowFile
    	FlowFile flowFile = session.get();
        if ( flowFile == null ) {
            return;
        }
        
        // TODO implement
        try {
        	InputStream contentInputStream = session.read(flowFile);
        	final byte[] contentBytes = getByteArray(contentInputStream);
        	
        	// Close the input stream
        	contentInputStream.close();
        	// I have to create a new ByteArrayInputStream b/c the pkts lib writer did not implement the close() method, so I have to manually close the input stream and use stored contentBytes.
        	final Pcap pcap = Pcap.openStream(new ByteArrayInputStream(contentBytes));
        	
        	
        	pcap.loop(new PacketHandler() {
        		@Override
        		public boolean nextPacket(Packet packet) throws IOException {
					// Get date of packet (assumed UTC from pcap header)
					Date date = new Date(packet.getArrivalTime() / 1000);
					// Date Format
					SimpleDateFormat formatter = new SimpleDateFormat(dateFormat);
					// Write attribute to flowfile
					session.putAttribute(flowFile, "pcap_timestamp", formatter.format(date));
        			return false; // False -> This instance does not want to read more packets.
        		}
        	});
        	
    		
        }
        catch (IOException e){
        	getLogger().error(e.getLocalizedMessage());
        	session.transfer(flowFile, REL_FAILURE);
        }
        
        session.transfer(flowFile, REL_SUCCESS);
    }
    private byte[] getByteArray(InputStream input) {
    	// https://stackoverflow.com/questions/1264709/convert-inputstream-to-byte-array-in-java
    	ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    	int nRead;
    	byte[] data = new byte[4096];

    	try {
			while ((nRead = input.read(data, 0, data.length)) != -1) {
			  buffer.write(data, 0, nRead);
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

    	return buffer.toByteArray();
    	
    }
}






