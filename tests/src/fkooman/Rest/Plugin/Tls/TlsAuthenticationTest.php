<?php

/**
 * Copyright 2014 François Kooman <fkooman@tuxed.net>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
namespace fkooman\Rest\Plugin\Tls;

use fkooman\Http\Request;
use PHPUnit_Framework_TestCase;

class TlsAuthenticationTest extends PHPUnit_Framework_TestCase
{
    private $certData = 'MIIDKTCCAhOgAwIBAgIQO3Z/9L1Ryj8zQb8A7b1AyDALBgkqhkiG9w0BAQswJDEiMCAGA1UEAwwZSW5kaWVDZXJ0IChpbmRpZWNlcnQubmV0KTAeFw0xNTA2MDIxNjM5NTBaFw0xNjA2MDIxNjM5NTBaMCsxKTAnBgNVBAMMIDAzZGQ2YmFkNDk4Nzg1Yjg3ZmJmZDQ5MWZkMzQ5ZmZmMIIBIDALBgkqhkiG9w0BAQEDggEPADCCAQoCggEBALqHBqVKWOEWiWRAF6XzEPe+c4/jshPh9NnvZlnAim626TMigI/AF+0T9yf6CMJsMpYX0OA+isEL0+5I9gmAoiE9pBBFD1sJYfUMcstvFtz4mtY9FFqBZrJKP7hQWqCNJ8mocb4I4Y+eOgceeMaBxzZuxITf1rApIujmW4LuFpHHdpRTiCaeDXHWp3EaE0vep+Vb6uNmPkHq8fgpZZcMXKz3npHJjNUeUSrxJ4fPluyphcRWAKfqKb0M1s/jWwvA7h7Ld1EAVKPiPjNSgtHUmz3ifMWizFER/ue4Q0b+9oUX2omFbTE+pOLW0KVMJj2d2Ni9HGyRTafALYIbaLkXZbMCAwEAAaNWMFQwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUlWaLhuukiWx6S5TBo3FFYGKskEAwCwYJKoZIhvcNAQELA4IBAQASg929lYTCHavPJ9niTorx8kN7mMpSYQE7lhvyv0S4x3LNPGGT+/Y4NSjLNIwwcMGzYtaBaTR+zderhPrlSV4uIVLWMgHyIY/IKms1p5YendiH7QNrdFjsPmKDhl/dqMy0ZnqgXKG7FMwhcUyxjNTmml9tdNCMMjwwiZAihn68eB4D4l5kUFlGXqliE1tqm3jWUOywsIAz9qVJFyEHEWiohoOCenTvFM8JUV8rThE+PgxunPjHA8iW22QoF4ADUTqxH4h24rIo4BodahdSKecNLQWeT9sYz50XBzbpXbiWef2d0RMnCi6k+oiuBZBBz630kSU6jpi1a8iyavTT8jEA';

    public function testTlsAuthCorrect()
    {
        $request = new Request(
            array(
                'SERVER_NAME' => 'www.example.org',
                'SERVER_PORT' => 80,
                'QUERY_STRING' => '',
                'REQUEST_URI' => '/',
                'SCRIPT_NAME' => '/index.php',
                'REQUEST_METHOD' => 'GET',
                'SSL_CLIENT_CERT' => $this->certData,
            )
        );
        $auth = new TlsAuthentication();
        $certParser = $auth->execute($request, array());
        $this->assertEquals('__e3IYuUIKu_reNjy8ZHZ2PBh_H11eM5Rqs_KzxiHGg', $certParser->getFingerprint('sha256', true));
    }

    /**
     * @expectedException fkooman\Http\Exception\ForbiddenException
     * @expectedExceptionMessage TLS client certificate missing
     */
    public function testTlsAuthNoCert()
    {
        $request = new Request(
            array(
                'SERVER_NAME' => 'www.example.org',
                'SERVER_PORT' => 80,
                'QUERY_STRING' => '',
                'REQUEST_URI' => '/',
                'SCRIPT_NAME' => '/index.php',
                'REQUEST_METHOD' => 'GET',
            )
        );
        $auth = new TlsAuthentication();
        $this->assertFalse($auth->execute($request, array()));
    }

    /**
     * @expectedException fkooman\Http\Exception\ForbiddenException
     * @expectedExceptionMessage TLS client certificate missing
     */
    public function testTlsEmptyCert()
    {
        $request = new Request(
            array(
                'SERVER_NAME' => 'www.example.org',
                'SERVER_PORT' => 80,
                'QUERY_STRING' => '',
                'REQUEST_URI' => '/',
                'SCRIPT_NAME' => '/index.php',
                'REQUEST_METHOD' => 'GET',
                'SSL_CLIENT_CERT' => '',
            )
        );
        $auth = new TlsAuthentication();
        $this->assertFalse($auth->execute($request, array()));
    }

    /**
     * @expectedException fkooman\Http\Exception\BadRequestException
     * @expectedExceptionMessage OpenSSL was unable to parse the certificate
     */
    public function testTlsAuthBrokenCert()
    {
        $request = new Request(
            array(
                'SERVER_NAME' => 'www.example.org',
                'SERVER_PORT' => 80,
                'QUERY_STRING' => '',
                'REQUEST_URI' => '/',
                'SCRIPT_NAME' => '/index.php',
                'REQUEST_METHOD' => 'GET',
                'SSL_CLIENT_CERT' => 'Not A+/\ Certificate',
            )
        );
        $auth = new TlsAuthentication();
        $this->assertFalse($auth->execute($request, array()));
    }
}
