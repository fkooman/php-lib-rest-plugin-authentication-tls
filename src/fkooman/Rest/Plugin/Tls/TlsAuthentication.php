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

use fkooman\X509\CertParser;
use fkooman\Http\Request;
use fkooman\Rest\ServicePluginInterface;
use fkooman\Http\Exception\ForbiddenException;
use fkooman\Http\Exception\BadRequestException;
use Exception;

class TlsAuthentication implements ServicePluginInterface
{
    public function execute(Request $request, array $routeConfig)
    {
        $certData = $request->getHeader('SSL_CLIENT_CERT');
        if (null === $certData || !is_string($certData) || 0 >= strlen($certData)) {
            throw new ForbiddenException('TLS client certificate missing in request');
        }

        try {
            $certParser = CertParser::fromPem($certData);

            return $certParser;
        } catch (Exception $e) {
            // something went wrong with parsing the certificate...
            throw new BadRequestException($e->getMessage());
        }
    }
}
