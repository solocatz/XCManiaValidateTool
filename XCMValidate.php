<?php
    
// XCMania Flight Computer Validate Program
// solocatx@gmail.com
class XCManiaValidator
{
    public $igcCore;
    public $sig;
    private $publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCxFcKg7r6kBHH+JFnuR71sGaHSJ0LssA4s539OmgY2oZOuNV2cnV0wAfhVR1S1YAair4n4CFEUWEvwOej6RydeDZniyKBQv8opnjA2S5kTqpfVMQFlmMUecQwCLnh5qWJOwohfewJrd34F37okTAeUs4Mih9okA+Jtqx+OlMOPowIDAQAB";

    function Validate()
    {
        return $this->VerifySig($this->igcCore, $this->sig);
    }

    function VerifySig($data, $sig)
    {
        $pub = chunk_split($this->publicKey, 64, "\n");
        $formatedKey = "-----BEGIN PUBLIC KEY-----\n$pub-----END PUBLIC KEY-----\n";

        $pkeyid = openssl_pkey_get_public($formatedKey);
        $result = openssl_verify($data, hex2bin($sig), $pkeyid);
        return $result;
    }

    function startsWith($string, $startString)
    {
        $len = strlen($startString);
        return (substr($string, 0, $len) === $startString);
    }

    function LoadIGCFromFile($fn)
    {
        $this->igcCore = "";
        $this->sig = "";
        $myfile = fopen($fn, "r") or die(1);
        // Output one line until end-of-file
        while (!feof($myfile)) {
            $line = trim(fgets($myfile));
            if (strlen($line) > 0) {
                if ($this->startsWith($line, "L")) continue;
                else if ($this->startsWith($line, "G")) $this->sig .= substr($line, 1);
                else $this->igcCore .= $line;
            }
        }
        fclose($myfile);
    }
}

$validator = new XCManiaValidator;
if ($argc == 2) {
    $igcFile = $argv[1];
    $validator->LoadIGCFromFile($igcFile);
    $result = $validator->Validate();
    if ($result > 0) {
        echo "Validate OK\n";
        exit(0);
    } else {
        echo "Validate Failed\n";
        exit(1);
    }
} else {
    echo "Usage: php verify.php <IGC File>\n\n";
    exit(2);
}
