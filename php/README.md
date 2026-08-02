# DomScan PHP SDK

Official PHP client for the [DomScan API](https://domscan.net/docs).

This SDK is generated from the shared endpoint manifest in this repository and covers the same 113 public non-session endpoints as the other official DomScan SDKs.

## Installation

```bash
mkdir -p packages
curl -L https://github.com/estevecastells/domscan-sdk/releases/latest/download/domscan-sdk-php.zip -o packages/domscan-sdk-php-0.2.0.zip
composer config repositories.domscan artifact packages
composer require estevecastells/domscan-sdk:0.2.0
```

## Quick Start

```php
<?php

require 'vendor/autoload.php';

$client = new \DomScan\Client();
$response = $client->availability()->checkDomainAvailability([
    'name' => 'launch',
    'tlds' => ['com', 'io', 'ai'],
    'prefer_cache' => true,
]);

var_dump($response);
```

## Resources

- Docs: [https://domscan.net/docs](https://domscan.net/docs)
- OpenAPI: [https://domscan.net/v1/openapi.json](https://domscan.net/v1/openapi.json)
- SDK hub: [../README.md](../README.md)
