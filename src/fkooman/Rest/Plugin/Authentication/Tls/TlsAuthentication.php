<?php

/**
 * Copyright 2015 François Kooman <fkooman@tuxed.net>.
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
namespace fkooman\Rest\Plugin\Authentication\Tls;

use fkooman\Http\Request;
use fkooman\Rest\Service;
use fkooman\Rest\Plugin\Authentication\AuthenticationPluginInterface;
use fkooman\Http\Exception\UnauthorizedException;
use fkooman\Http\Exception\BadRequestException;
use fkooman\Base64\Base64;
use InvalidArgumentException;

class TlsAuthentication implements AuthenticationPluginInterface
{
    /** @var array */
    private $authParams;

    public function __construct(array $authParams = array())
    {
        $this->authParams = $authParams;
    }

    public function init(Service $service)
    {
        // NOP
    }

    public function isAuthenticated(Request $request)
    {
        $certData = self::getCertData($request);
        if (false === $certData) {
            return false;
        }

        $derString = self::pemToDer($certData);
        if (false === $derString) {
            throw new BadRequestException('invalid certificate');
        }

        return new CertInfo($derString);
    }

    public function requestAuthentication(Request $request)
    {
        // if we reach here, authentication failed and can't be fixed, no
        // matter what. Possibly the user cancelled the certificate popup, or
        // has no certificate...
        $e = new UnauthorizedException(
            'no_certificate',
            'TLS client certificate missing in request'
        );
        $e->addScheme('TLS', $this->authParams);

        throw $e;
    }

    private static function getCertData(Request $request)
    {
        // sometimes Apache/PHP uses SSL_CLIENT_CERT,
        // sometimes REDIRECT_SSL_CLIENT_CERT, do not know exactly why...
        $certKeys = array('SSL_CLIENT_CERT', 'REDIRECT_SSL_CLIENT_CERT');
        foreach ($certKeys as $certKey) {
            $certData = $request->getHeader($certKey);
            if (null !== $certData && 0 !== strlen($certData)) {
                return $certData;
            }
        }

        return false;
    }

    private static function pemToDer($certData)
    {
        $encodedString = preg_replace(
            '/.*-----BEGIN CERTIFICATE-----(.*)-----END CERTIFICATE-----.*/msU',
            '${1}',
            $certData
        );

        if (!is_string($encodedString)) {
            return false;
        }
        $encodedString = str_replace(
            array(' ', "\t", "\n", "\r", "\0", "\x0B"),
            '',
            $encodedString
        );

        try {
            return Base64::decode($encodedString);
        } catch (InvalidArgumentException $e) {
            return false;
        }
    }
}
