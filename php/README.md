# DomScan PHP SDK

Official PHP client for the [DomScan API](https://domscan.net/docs).

This SDK is generated from the shared endpoint manifest in this repository and covers the same 79 public non-session endpoints as the other official DomScan SDKs.

## Installation

```bash
composer require estevecastells/domscan-sdk
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
