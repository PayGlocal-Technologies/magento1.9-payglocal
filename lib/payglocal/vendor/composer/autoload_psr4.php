<?php

// autoload_psr4.php @generated by Composer

$vendorDir = dirname(dirname(__FILE__));
$baseDir = dirname($vendorDir);

return array(
    'Symfony\\Polyfill\\Mbstring\\' => array($vendorDir . '/symfony/polyfill-mbstring'),
    'Safe\\' => array($vendorDir . '/thecodingmachine/safe/lib', $vendorDir . '/thecodingmachine/safe/deprecated', $vendorDir . '/thecodingmachine/safe/generated'),
    'Psr\\Http\\Message\\' => array($vendorDir . '/psr/http-factory/src', $vendorDir . '/psr/http-message/src'),
    'Psr\\Http\\Client\\' => array($vendorDir . '/psr/http-client/src'),
    'Jose\\Component\\Signature\\Algorithm\\' => array($vendorDir . '/web-token/jwt-signature-algorithm-ecdsa', $vendorDir . '/web-token/jwt-signature-algorithm-eddsa', $vendorDir . '/web-token/jwt-signature-algorithm-experimental', $vendorDir . '/web-token/jwt-signature-algorithm-hmac', $vendorDir . '/web-token/jwt-signature-algorithm-none', $vendorDir . '/web-token/jwt-signature-algorithm-rsa'),
    'Jose\\Component\\Signature\\' => array($vendorDir . '/web-token/jwt-signature'),
    'Jose\\Component\\KeyManagement\\' => array($vendorDir . '/web-token/jwt-key-mgmt'),
    'Jose\\Component\\Encryption\\Algorithm\\KeyEncryption\\' => array($vendorDir . '/web-token/jwt-encryption-algorithm-aesgcmkw', $vendorDir . '/web-token/jwt-encryption-algorithm-aeskw', $vendorDir . '/web-token/jwt-encryption-algorithm-dir', $vendorDir . '/web-token/jwt-encryption-algorithm-ecdh-es', $vendorDir . '/web-token/jwt-encryption-algorithm-pbes2', $vendorDir . '/web-token/jwt-encryption-algorithm-rsa'),
    'Jose\\Component\\Encryption\\Algorithm\\ContentEncryption\\' => array($vendorDir . '/web-token/jwt-encryption-algorithm-aescbc', $vendorDir . '/web-token/jwt-encryption-algorithm-aesgcm'),
    'Jose\\Component\\Encryption\\Algorithm\\' => array($vendorDir . '/web-token/jwt-encryption-algorithm-experimental'),
    'Jose\\Component\\Encryption\\' => array($vendorDir . '/web-token/jwt-encryption'),
    'Jose\\Component\\Core\\Util\\Ecc\\' => array($vendorDir . '/web-token/jwt-util-ecc'),
    'Jose\\Component\\Core\\' => array($vendorDir . '/web-token/jwt-core'),
    'FG\\' => array($vendorDir . '/fgrosse/phpasn1/lib'),
    'Brick\\Math\\' => array($vendorDir . '/brick/math/src'),
    'Base64Url\\' => array($vendorDir . '/spomky-labs/base64url/src'),
    'AESKW\\' => array($vendorDir . '/spomky-labs/aes-key-wrap/src'),
);
