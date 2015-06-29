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
    private $certData = '-----BEGIN CERTIFICATE-----
MIIDKTCCAhOgAwIBAgIQO3Z/9L1Ryj8zQb8A7b1AyDALBgkqhkiG9w0BAQswJDEi
MCAGA1UEAwwZSW5kaWVDZXJ0IChpbmRpZWNlcnQubmV0KTAeFw0xNTA2MDIxNjM5
NTBaFw0xNjA2MDIxNjM5NTBaMCsxKTAnBgNVBAMMIDAzZGQ2YmFkNDk4Nzg1Yjg3
ZmJmZDQ5MWZkMzQ5ZmZmMIIBIDALBgkqhkiG9w0BAQEDggEPADCCAQoCggEBALqH
BqVKWOEWiWRAF6XzEPe+c4/jshPh9NnvZlnAim626TMigI/AF+0T9yf6CMJsMpYX
0OA+isEL0+5I9gmAoiE9pBBFD1sJYfUMcstvFtz4mtY9FFqBZrJKP7hQWqCNJ8mo
cb4I4Y+eOgceeMaBxzZuxITf1rApIujmW4LuFpHHdpRTiCaeDXHWp3EaE0vep+Vb
6uNmPkHq8fgpZZcMXKz3npHJjNUeUSrxJ4fPluyphcRWAKfqKb0M1s/jWwvA7h7L
d1EAVKPiPjNSgtHUmz3ifMWizFER/ue4Q0b+9oUX2omFbTE+pOLW0KVMJj2d2Ni9
HGyRTafALYIbaLkXZbMCAwEAAaNWMFQwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQM
MAoGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUlWaLhuukiWx6
S5TBo3FFYGKskEAwCwYJKoZIhvcNAQELA4IBAQASg929lYTCHavPJ9niTorx8kN7
mMpSYQE7lhvyv0S4x3LNPGGT+/Y4NSjLNIwwcMGzYtaBaTR+zderhPrlSV4uIVLW
MgHyIY/IKms1p5YendiH7QNrdFjsPmKDhl/dqMy0ZnqgXKG7FMwhcUyxjNTmml9t
dNCMMjwwiZAihn68eB4D4l5kUFlGXqliE1tqm3jWUOywsIAz9qVJFyEHEWiohoOC
enTvFM8JUV8rThE+PgxunPjHA8iW22QoF4ADUTqxH4h24rIo4BodahdSKecNLQWe
T9sYz50XBzbpXbiWef2d0RMnCi6k+oiuBZBBz630kSU6jpi1a8iyavTT8jEA
-----END CERTIFICATE-----
';

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
        $certInfo = $auth->execute($request, array());
        $this->assertEquals('__e3IYuUIKu_reNjy8ZHZ2PBh_H11eM5Rqs_KzxiHGg', $certInfo->getUserId());
    }

    public function testTlsAuthCorrectRedirectSslClietCert()
    {
        $request = new Request(
            array(
                'SERVER_NAME' => 'www.example.org',
                'SERVER_PORT' => 80,
                'QUERY_STRING' => '',
                'REQUEST_URI' => '/',
                'SCRIPT_NAME' => '/index.php',
                'REQUEST_METHOD' => 'GET',
                'REDIRECT_SSL_CLIENT_CERT' => $this->certData,
            )
        );
        $auth = new TlsAuthentication();
        $certInfo = $auth->execute($request, array());
        $this->assertEquals('__e3IYuUIKu_reNjy8ZHZ2PBh_H11eM5Rqs_KzxiHGg', $certInfo->getUserId());
    }

    /**
     * @expectedException fkooman\Http\Exception\UnauthorizedException
     * @expectedExceptionMessage no_credentials
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
     * @expectedException fkooman\Http\Exception\UnauthorizedException
     * @expectedExceptionMessage no_credentials
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
        $auth->execute($request, array());
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
        $auth->execute($request, array());
    }

    /**
     * @expectedException fkooman\Http\Exception\BadRequestException
     * @expectedExceptionMessage OpenSSL was unable to parse the certificate
     */
    public function testAttemptWhileNotRequired()
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
        $auth->execute($request, array('requireAuth' => false));
    }

    public function testNotRequired()
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
        $this->assertNull($auth->execute($request, array('requireAuth' => false)));
    }
}
