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

namespace fkooman\Rest\Plugin\Tls;

use fkooman\X509\CertParser;
use fkooman\Http\Request;
use fkooman\Rest\Plugin\Authentication\AuthenticationPluginInterface;
use fkooman\Http\Exception\UnauthorizedException;
use fkooman\Http\Exception\BadRequestException;
use Exception;

class TlsAuthentication implements AuthenticationPluginInterface
{
    /** @var array */
    private $authParams;

    public function __construct(array $authParams = array())
    {
        $this->authParams = $authParams;
    }

    public function getScheme()
    {
        return 'TLS';
    }

    public function getAuthParams()
    {
        return $this->authParams;
    }

    public function isAttempt(Request $request)
    {
        return false !== $this->getCertData($request);
    }

    private function getCertData(Request $request)
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

    public function execute(Request $request, array $routeConfig)
    {
        if ($this->isAttempt($request)) {
            try {
                $certData = $this->getCertData($request);

                return new CertInfo(CertParser::fromPem($certData));
            } catch (Exception $e) {
                // something went wrong with parsing the certificate...
                throw new BadRequestException($e->getMessage());
            }
        }

        // no attempt
        if (array_key_exists('requireAuth', $routeConfig)) {
            if (!$routeConfig['requireAuth']) {
                // no authentication required
                return;
            }
        }

        // no attempt, but authentication required
        $e = new UnauthorizedException(
            'no_credentials',
            'TLS client certificate missing in request'
        );
        $e->addScheme('TLS', $this->authParams);
        throw $e;
    }
}
