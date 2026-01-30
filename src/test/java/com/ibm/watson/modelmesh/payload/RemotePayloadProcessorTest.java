/*
 * Copyright 2023 IBM Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package com.ibm.watson.modelmesh.payload;

import java.io.IOException;
import java.net.URI;
import java.security.NoSuchAlgorithmException;

import io.grpc.Metadata;
import io.grpc.Status;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class RemotePayloadProcessorTest {

    void testDestinationUnreachable() throws IOException {
        URI uri = URI.create("http://this-does-not-exist:123");
        try (RemotePayloadProcessor remotePayloadProcessor = new RemotePayloadProcessor(uri)) {
            String id = "123";
            String modelId = "456";
            String method = "predict";
            Status kind = Status.INVALID_ARGUMENT;
            Metadata metadata = new Metadata();
            metadata.put(Metadata.Key.of("foo", Metadata.ASCII_STRING_MARSHALLER), "bar");
            metadata.put(Metadata.Key.of("binary-bin", Metadata.BINARY_BYTE_MARSHALLER), "string".getBytes());
            ByteBuf data = Unpooled.buffer(4);
            Payload payload = new Payload(id, modelId, method, metadata, data, kind);
            assertFalse(remotePayloadProcessor.process(payload));
        }
    }

    @Test
    void testDestinationUnreachableHTTPS() throws IOException, NoSuchAlgorithmException {
        URI uri = URI.create("https://this-does-not-exist:123");
        SSLContext sslContext = SSLContext.getDefault();
        SSLParameters sslParameters = sslContext.getDefaultSSLParameters();
        try (RemotePayloadProcessor remotePayloadProcessor = new RemotePayloadProcessor(uri, sslContext, sslParameters)) {
            String id = "123";
            String modelId = "456";
            String method = "predict";
            Status kind = Status.INVALID_ARGUMENT;
            Metadata metadata = new Metadata();
            metadata.put(Metadata.Key.of("foo", Metadata.ASCII_STRING_MARSHALLER), "bar");
            metadata.put(Metadata.Key.of("binary-bin", Metadata.BINARY_BYTE_MARSHALLER), "string".getBytes());
            ByteBuf data = Unpooled.buffer(4);
            Payload payload = new Payload(id, modelId, method, metadata, data, kind);
            assertFalse(remotePayloadProcessor.process(payload));
        }
    }

    @Test
    void testSSRFProtection_Localhost() {
        assertThrows(IllegalArgumentException.class, () -> {
            new RemotePayloadProcessor(URI.create("http://localhost:8080/endpoint"));
        }, "Should reject localhost");
    }

    @Test
    void testSSRFProtection_LoopbackIPv4() {
        assertThrows(IllegalArgumentException.class, () -> {
            new RemotePayloadProcessor(URI.create("http://127.0.0.1:8080/endpoint"));
        }, "Should reject 127.0.0.1");
    }

    @Test
    void testSSRFProtection_LoopbackIPv6() {
        assertThrows(IllegalArgumentException.class, () -> {
            new RemotePayloadProcessor(URI.create("http://[::1]:8080/endpoint"));
        }, "Should reject ::1");
    }

    @Test
    void testSSRFProtection_PrivateIP_10() {
        assertThrows(IllegalArgumentException.class, () -> {
            new RemotePayloadProcessor(URI.create("http://10.0.0.1:8080/endpoint"));
        }, "Should reject 10.x.x.x private IP");
    }

    @Test
    void testSSRFProtection_PrivateIP_192() {
        assertThrows(IllegalArgumentException.class, () -> {
            new RemotePayloadProcessor(URI.create("http://192.168.1.1:8080/endpoint"));
        }, "Should reject 192.168.x.x private IP");
    }

    @Test
    void testSSRFProtection_PrivateIP_172() {
        assertThrows(IllegalArgumentException.class, () -> {
            new RemotePayloadProcessor(URI.create("http://172.16.0.1:8080/endpoint"));
        }, "Should reject 172.16-31.x.x private IP");
    }

    @Test
    void testSSRFProtection_AWSMetadata() {
        assertThrows(IllegalArgumentException.class, () -> {
            new RemotePayloadProcessor(URI.create("http://169.254.169.254/latest/meta-data/"));
        }, "Should reject AWS metadata service");
    }

    @Test
    void testSSRFProtection_NullURI() {
        assertThrows(IllegalArgumentException.class, () -> {
            new RemotePayloadProcessor(null);
        }, "Should reject null URI");
    }
}