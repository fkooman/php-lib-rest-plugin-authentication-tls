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
require_once dirname(__DIR__).'/vendor/autoload.php';

use fkooman\Rest\Service;
use fkooman\Rest\Plugin\Tls\TlsAuthentication;
use fkooman\X509\CertParser;

$service = new Service();
$pluginRegistry = new PluginRegistry();
$pluginRegistry->registerDefaultPlugin(
    new TlsAuthentication()
);
$service->setPluginRegistry($pluginRegistry);

$service->get(
    '/getMyUserId',
    function (CertParser $certParser) {
        return sprintf('Hello %s', $u->getName());
    }
);

$service->run()->sendResponse();
