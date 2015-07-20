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

use fkooman\Rest\Plugin\Authentication\UserInfoInterface;
use fkooman\X509\CertParser;
use fkooman\Base64\Base64Url;

class CertInfo implements UserInfoInterface
{
    /** @var \fkooman\X509\CertParser */
    private $certParser;

    public function __construct(CertParser $certParser)
    {
        $this->certParser = $certParser;
    }

    public function getUserId()
    {
        return Base64Url::encode($this->certParser->getFingerprint('sha256'));
    }
}
